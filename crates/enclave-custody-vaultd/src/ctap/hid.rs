//! CTAPHID framing (CTAP 2.1 §11.2): 64-byte reports, initialization packet
//! `CID(4) ‖ CMD|0x80 ‖ BCNT(2) ‖ DATA(57)` and continuation packets
//! `CID(4) ‖ SEQ(0..=0x7f) ‖ DATA(59)`.

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};

/// HID report size.
pub const REPORT: usize = 64;
/// Broadcast channel.
pub const BROADCAST_CID: u32 = 0xffff_ffff;
/// CTAPHID_INIT.
pub const CMD_INIT: u8 = 0x06;
/// CTAPHID_CBOR.
pub const CMD_CBOR: u8 = 0x10;
/// CTAPHID_ERROR.
pub const CMD_ERROR: u8 = 0x3f;
/// CTAPHID_KEEPALIVE.
pub const CMD_KEEPALIVE: u8 = 0x3b;
/// Max message size (`57 + 128 * 59`).
pub const MAX_MESSAGE: usize = 57 + 128 * 59;

/// A raw HID device: write one 64-byte output report / read one input report.
pub trait HidDevice: std::fmt::Debug {
    /// Write one report.
    fn write_report(&mut self, report: &[u8; REPORT]) -> EnclaveResult<()>;
    /// Read one report (blocking with the device's timeout).
    fn read_report(&mut self) -> EnclaveResult<[u8; REPORT]>;
    /// USB topology depth from the Apple root controller (1 = root port).
    fn hub_depth(&self) -> u8;
    /// Bind the uniquely selected native USB instance to removal monitoring.
    /// Software transports have no USB registry and retain their own lifecycle.
    fn bind_selected_instance(&mut self) -> EnclaveResult<()> {
        Ok(())
    }
    /// Original successfully singleton-bound native handle and owner lifetime.
    /// Software, candidate and paired transports cannot supply this capability.
    fn selected_transport_lifetime(
        &self,
    ) -> EnclaveResult<super::selected_transport_lifetime::SelectedTransportLifetime> {
        Err(err!(EACCES, "HID_SELECTED_TRANSPORT_UNAVAILABLE"))
    }
    /// Original ceremony deadline in this host's continuous-clock nanoseconds.
    fn deadline_ns(&self) -> Option<u64> {
        None
    }
    /// Scope native blocking reads to the original deadline. Fixtures that do
    /// not block may use the default; transact still checks advertised deadlines.
    fn set_deadline_ns(&mut self, _deadline: Option<u64>) -> EnclaveResult<()> {
        Ok(())
    }

    /// Concrete software fixture access. Native devices always return None,
    /// even in a test build whose dev-dependencies enable simulation.
    #[cfg(any(test, feature = "simulation"))]
    fn virtual_authenticator(
        &mut self,
    ) -> Option<&mut super::virtual_device::VirtualAuthenticator> {
        None
    }
}

/// Split a message into reports.
pub fn packetize(cid: u32, cmd: u8, data: &[u8]) -> EnclaveResult<Vec<[u8; REPORT]>> {
    if data.len() > MAX_MESSAGE {
        fail!(E2BIG, "CTAPHID_MESSAGE_TOO_LARGE");
    }
    let mut out = Vec::new();
    let mut p = [0u8; REPORT];
    p[..4].copy_from_slice(&cid.to_be_bytes());
    p[4] = cmd | 0x80;
    p[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
    let first = data.len().min(57);
    p[7..7 + first].copy_from_slice(&data[..first]);
    out.push(p);
    for (seq, chunk) in data[first..].chunks(59).enumerate() {
        let mut c = [0u8; REPORT];
        c[..4].copy_from_slice(&cid.to_be_bytes());
        c[4] = seq as u8;
        c[5..5 + chunk.len()].copy_from_slice(chunk);
        out.push(c);
    }
    Ok(out)
}

/// Incremental reassembler.
#[derive(Debug, Default)]
pub struct Reassembler {
    cid: u32,
    cmd: u8,
    total: usize,
    buf: Vec<u8>,
    next_seq: u8,
    started: bool,
}

impl Reassembler {
    /// Feed one report. Returns `Some((cmd, payload))` when complete.
    /// Keep-alive packets are skipped transparently.
    pub fn feed(
        &mut self,
        expect_cid: u32,
        r: &[u8; REPORT],
    ) -> EnclaveResult<Option<(u8, Vec<u8>)>> {
        let cid = u32::from_be_bytes([r[0], r[1], r[2], r[3]]);
        if cid != expect_cid {
            // Traffic for another channel (another uid=501 process driving the key).
            fail!(EAGAIN, "CTAPHID_FOREIGN_CHANNEL", "cid {cid:08x}");
        }
        if r[4] & 0x80 != 0 {
            let cmd = r[4] & 0x7f;
            if cmd == CMD_KEEPALIVE {
                if u16::from_be_bytes([r[5], r[6]]) != 1 || !matches!(r[7], 1 | 2) {
                    fail!(EINVAL, "CTAPHID_KEEPALIVE_INVALID");
                }
                return Ok(None);
            }
            if self.started {
                fail!(EINVAL, "CTAPHID_INTERLEAVED_RESPONSE");
            }
            let total = u16::from_be_bytes([r[5], r[6]]) as usize;
            if total > MAX_MESSAGE {
                fail!(E2BIG, "CTAPHID_MESSAGE_TOO_LARGE");
            }
            *self = Self {
                cid,
                cmd,
                total,
                buf: Vec::with_capacity(total),
                next_seq: 0,
                started: true,
            };
            let n = total.min(57);
            self.buf.extend_from_slice(&r[7..7 + n]);
        } else {
            if !self.started || r[4] != self.next_seq {
                fail!(
                    EINVAL,
                    "CTAPHID_SEQUENCE",
                    "unexpected continuation seq {}",
                    r[4]
                );
            }
            self.next_seq += 1;
            let n = (self.total - self.buf.len()).min(59);
            self.buf.extend_from_slice(&r[5..5 + n]);
        }
        if self.buf.len() == self.total {
            self.started = false;
            let _ = self.cid;
            return Ok(Some((self.cmd, std::mem::take(&mut self.buf))));
        }
        Ok(None)
    }
}

/// Refuse frames after the original continuous-clock ceremony deadline.
pub fn check_deadline(dev: &dyn HidDevice) -> EnclaveResult<()> {
    if dev
        .deadline_ns()
        .is_some_and(|deadline| enclave_core::power::continuous_time_ns() >= deadline)
    {
        fail!(ETIMEDOUT, "CTAPHID_DEADLINE_EXCEEDED");
    }
    Ok(())
}

/// Send a message and read the complete response on `cid`.
pub fn transact(
    dev: &mut dyn HidDevice,
    cid: u32,
    cmd: u8,
    data: &[u8],
) -> EnclaveResult<(u8, Vec<u8>)> {
    for p in packetize(cid, cmd, data)? {
        check_deadline(dev)?;
        dev.write_report(&p)?;
        check_deadline(dev)?;
    }
    let mut r = Reassembler::default();
    // Bounded: at most 129 packets plus keep-alives.
    for _ in 0..4096 {
        check_deadline(dev)?;
        let rep = dev.read_report()?;
        check_deadline(dev)?;
        if let Some((rcmd, payload)) = r.feed(cid, &rep)? {
            if rcmd == CMD_ERROR {
                fail!(
                    EIO,
                    "CTAPHID_ERROR",
                    "code {:#x}",
                    payload.first().copied().unwrap_or(0)
                );
            }
            return Ok((rcmd, payload));
        }
    }
    Err(err!(ETIMEDOUT, "CTAPHID_TIMEOUT"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_large_message() {
        let data: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let pk = packetize(0x01020304, CMD_CBOR, &data).unwrap();
        assert_eq!(pk.len(), 1 + (1000usize - 57).div_ceil(59));
        let mut r = Reassembler::default();
        let mut out = None;
        for p in &pk {
            out = r.feed(0x01020304, p).unwrap().or(out);
        }
        assert_eq!(out.unwrap(), (CMD_CBOR, data));
    }

    #[test]
    fn foreign_channel_and_bad_sequence_rejected() {
        let pk = packetize(7, CMD_CBOR, &[0u8; 100]).unwrap();
        let mut r = Reassembler::default();
        assert!(r.feed(8, &pk[0]).unwrap_err().is("CTAPHID_FOREIGN_CHANNEL"));
        let mut r = Reassembler::default();
        r.feed(7, &pk[0]).unwrap();
        let mut bad = pk[1];
        bad[4] = 5;
        assert!(r.feed(7, &bad).is_err());
        assert!(packetize(1, 1, &vec![0u8; MAX_MESSAGE + 1]).is_err());
    }
    #[test]
    fn malformed_keepalive_and_interleaved_response_cannot_reset_message() {
        let mut reader = Reassembler::default();
        let incomplete = packetize(7, CMD_CBOR, &[0; 100]).unwrap();
        reader.feed(7, &incomplete[0]).unwrap();
        let keepalive = packetize(7, CMD_KEEPALIVE, &[1]).unwrap();
        assert!(reader.feed(7, &keepalive[0]).unwrap().is_none());
        assert!(reader
            .feed(7, &incomplete[0])
            .unwrap_err()
            .is("CTAPHID_INTERLEAVED_RESPONSE"));
        for payload in [vec![], vec![0], vec![3], vec![1, 2]] {
            let packet = packetize(7, CMD_KEEPALIVE, &payload).unwrap();
            assert!(Reassembler::default()
                .feed(7, &packet[0])
                .unwrap_err()
                .is("CTAPHID_KEEPALIVE_INVALID"));
        }
    }
}
