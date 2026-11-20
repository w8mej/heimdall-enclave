//! Explicit physical selection diagnostic; separate from INIT/GetInfo-only mode.
//! A successful selection response is not a signed UP assertion or key identity.
use enclave_core::{err, fail, error::EnclaveResult};
use enclave_custody_vaultd::ctap::{client::CtapClient, hid::{self, HidDevice, REPORT, BROADCAST_CID, CMD_INIT, CMD_CBOR}};
use std::{time::{Duration, Instant}, sync::atomic::{AtomicBool, Ordering}};

const SELECTION: u8 = 0x0b;
const CANCEL: u8 = 0x11;
const KEEPALIVE_CANCEL: u8 = 0x2d;
const LIMIT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cancellation { NotNeeded, DeadlineUnavailable, SentUnconfirmed, ConfirmedStatus, WriteFailed }

#[derive(Debug)]
struct SelectionDevice<D> {
    inner: D,
    end: Instant,
    boot_end: u64,
    armed: Option<u32>,
    attempted: bool,
    init_count: u8, info_count: u8, init_nonce: Option<[u8;8]>, allocated: Option<u32>,
    pending: bool, cancel_attempted: bool, cancellation: Cancellation,
}
impl<D: HidDevice> SelectionDevice<D> {
    fn new(mut inner: D, end: Instant, boot_end: u64) -> EnclaveResult<Self> {
        let boot_end = inner.deadline_ns().map_or(boot_end, |original| original.min(boot_end));
        inner.set_deadline_ns(Some(boot_end))?;
        let owner = Self { inner, end, boot_end, armed: None, attempted: false,
            init_count: 0, info_count: 0, init_nonce: None, allocated: None, pending: false,
            cancel_attempted: false, cancellation: Cancellation::NotNeeded };
        owner.current()?;
        Ok(owner)
    }
    fn current(&self) -> EnclaveResult<()> {
        let now = enclave_core::power::continuous_time_ns();
        if now == u64::MAX || now >= self.boot_end || Instant::now() >= self.end {
            fail!(ETIMEDOUT, "FIDO_SELECTION_DIAGNOSTIC_DEADLINE");
        }
        Ok(())
    }
    fn arm(&mut self, cid: u32) -> EnclaveResult<()> {
        self.current()?;
        if cid == 0 || cid == BROADCAST_CID || self.armed.is_some() || self.attempted
            || self.allocated != Some(cid) || self.init_nonce.is_some() || self.init_count != 2 || self.info_count != 1 {
            fail!(EACCES, "FIDO_SELECTION_DIAGNOSTIC_ALREADY_ARMED");
        }
        self.armed = Some(cid);
        Ok(())
    }
    fn cancel_pending(&mut self, cid: u32) {
        if !self.pending || self.armed != Some(cid) || self.cancel_attempted { return; }
        if self.current().is_err() { self.cancellation = Cancellation::DeadlineUnavailable; return; }
        let report = match hid::packetize(cid, CANCEL, &[]) { Ok(reports) => reports[0], Err(_) => return };
        if self.write_report(&report).is_err() { self.cancellation = Cancellation::WriteFailed; return; }
        self.cancellation = Cancellation::SentUnconfirmed;
        let mut response = hid::Reassembler::default();
        for _ in 0..4096 {
            let report = match self.read_report() { Ok(report) => report, Err(_) => return };
            match response.feed(cid, &report) {
                Ok(Some((CMD_CBOR, payload))) if payload == [KEEPALIVE_CANCEL] => {
                    self.pending = false; self.cancellation = Cancellation::ConfirmedStatus; return;
                },
                Ok(None) => {},
                _ => return,
            }
        }
    }
}
impl<D: HidDevice> HidDevice for SelectionDevice<D> {
    fn write_report(&mut self, report: &[u8; REPORT]) -> EnclaveResult<()> {
        self.current()?;
        let cid = u32::from_be_bytes(report[..4].try_into().expect("four bytes"));
        let len = u16::from_be_bytes([report[5], report[6]]);
        let init = report[4] == (CMD_INIT | 0x80) && cid == BROADCAST_CID
            && len == 8 && report[15..].iter().all(|byte| *byte == 0)
            && self.init_nonce.is_none() && self.armed.is_none() && !self.attempted
            && (self.init_count == 0 || self.init_count == 1 && self.info_count == 1);
        let single = report[4] == (CMD_CBOR | 0x80) && cid != 0 && cid != BROADCAST_CID
            && len == 1 && report[8..].iter().all(|byte| *byte == 0);
        let info = single && report[7] == 0x04 && self.allocated == Some(cid)
            && self.init_nonce.is_none() && self.init_count == 1 && self.info_count == 0 && self.armed.is_none();
        let selection = single && report[7] == SELECTION && self.armed == Some(cid) && !self.attempted;
        let cancel = report[4] == (CANCEL | 0x80) && len == 0 && self.armed == Some(cid)
            && self.pending && self.attempted && !self.cancel_attempted && report[7..].iter().all(|byte| *byte == 0);
        if !init && !info && !selection && !cancel {
            fail!(EPERM, "FIDO_SELECTION_DIAGNOSTIC_OPERATION_FORBIDDEN");
        }
        // Consume BEFORE the native write; an uncertain send is never retried.
        if init {
            self.init_count += 1;
            self.init_nonce = Some(report[7..15].try_into().expect("eight bytes"));
            self.allocated = None;
        }
        if info { self.info_count += 1; }
        if selection { self.attempted = true; self.pending = true; }
        if cancel { self.cancel_attempted = true; }
        self.inner.write_report(report)?;
        self.current()
    }
    fn read_report(&mut self) -> EnclaveResult<[u8; REPORT]> {
        self.current()?;
        let report = self.inner.read_report()?;
        self.current()?;
        if let Some(nonce) = self.init_nonce {
            let cid = u32::from_be_bytes(report[..4].try_into().expect("four bytes"));
            if cid != BROADCAST_CID || report[4] != (CMD_INIT | 0x80)
                || u16::from_be_bytes([report[5],report[6]]) != 17 || report[7..15] != nonce {
                fail!(EACCES, "FIDO_SELECTION_DIAGNOSTIC_INIT_BINDING");
            }
            let allocated = u32::from_be_bytes(report[15..19].try_into().expect("four bytes"));
            if allocated == 0 || allocated == BROADCAST_CID { fail!(EACCES,"FIDO_SELECTION_DIAGNOSTIC_INIT_BINDING"); }
            self.allocated = Some(allocated); self.init_nonce = None;
        }
        Ok(report)
    }
    fn hub_depth(&self) -> u8 { self.inner.hub_depth() }
    fn deadline_ns(&self) -> Option<u64> { Some(self.boot_end) }
    fn set_deadline_ns(&mut self, end: Option<u64>) -> EnclaveResult<()> {
        let end = end.ok_or_else(|| err!(EACCES, "FIDO_SELECTION_DIAGNOSTIC_NO_DEADLINE_EXTENSION"))?;
        if end > self.boot_end { fail!(EACCES, "FIDO_SELECTION_DIAGNOSTIC_NO_DEADLINE_EXTENSION"); }
        self.boot_end = end;
        self.inner.set_deadline_ns(Some(end))
    }
}

fn selection<D: HidDevice>(device: &mut SelectionDevice<D>, expected: &[u8; 16]) -> EnclaveResult<()> {
    selection_with_cancel(device, expected, &AtomicBool::new(false))
}
fn selection_with_cancel<D: HidDevice>(device: &mut SelectionDevice<D>, expected: &[u8;16], cancelled: &AtomicBool) -> EnclaveResult<()> {
    if cancelled.load(Ordering::SeqCst) { fail!(EACCES,"FIDO_SELECTION_DIAGNOSTIC_CANCELLED"); }
    let info = CtapClient::open(device)?.get_info()?;
    if &info.aaguid != expected { fail!(EACCES, "FIDO_SELECTION_DIAGNOSTIC_MODEL_MISMATCH"); }
    if !info.versions.iter().any(|version| version == "FIDO_2_1") {
        fail!(ENOSYS, "FIDO_SELECTION_DIAGNOSTIC_CTAP21_REQUIRED");
    }
    // Allocate a new channel on this SAME open handle. CtapClient deliberately
    // keeps its own CID private; no credential/assertion/PIN API is used here.
    let nonce = enclave_core::rng::bytes32();
    let nonce = &nonce[..8];
    let (command, response) = hid::transact(device, BROADCAST_CID, CMD_INIT, nonce)?;
    if command != CMD_INIT || response.len() != 17 || &response[..8] != nonce {
        fail!(EACCES, "FIDO_SELECTION_DIAGNOSTIC_INIT_BINDING");
    }
    let cid = u32::from_be_bytes(response[8..12].try_into().expect("four bytes"));
    device.arm(cid)?;
    let result = selection_exchange(device, cid, cancelled);
    if result.is_err() { device.cancel_pending(cid); }
    let (command, response) = result?;
    if command != CMD_CBOR { device.cancel_pending(cid); }
    if command == CMD_CBOR { device.pending = false; }
    if command != CMD_CBOR || response.len() != 1 {
        fail!(EACCES, "FIDO_SELECTION_DIAGNOSTIC_RESPONSE_SHAPE");
    }
    match response[0] {
        0 => device.current(),
        1 => Err(err!(ENOSYS, "FIDO_SELECTION_DIAGNOSTIC_UNSUPPORTED")),
        0x2f => Err(err!(ETIMEDOUT,"FIDO_SELECTION_DIAGNOSTIC_TOUCH_TIMEOUT")),
        KEEPALIVE_CANCEL => Err(err!(EACCES,"FIDO_SELECTION_DIAGNOSTIC_CANCELLED")),
        _ => Err(err!(EACCES, "FIDO_SELECTION_DIAGNOSTIC_REFUSED")),
    }
}

// Reads and cancellation remain under BOTH original clocks. A synchronous
// native read may return only at its endpoint; interrupt is observed at the
// next report boundary, not claimed an immediate native cancellation bound.
fn selection_exchange<D:HidDevice>(device:&mut SelectionDevice<D>, cid:u32, cancelled:&AtomicBool)
    -> EnclaveResult<(u8,Vec<u8>)> {
    if cancelled.load(Ordering::SeqCst) { fail!(EACCES,"FIDO_SELECTION_DIAGNOSTIC_CANCELLED"); }
    device.write_report(&hid::packetize(cid,CMD_CBOR,&[SELECTION])?[0])?;
    let mut response = hid::Reassembler::default();
    for _ in 0..4096 {
        if cancelled.load(Ordering::SeqCst) { fail!(EACCES,"FIDO_SELECTION_DIAGNOSTIC_CANCELLED"); }
        let report = device.read_report()?;
        if cancelled.load(Ordering::SeqCst) { fail!(EACCES,"FIDO_SELECTION_DIAGNOSTIC_CANCELLED"); }
        if let Some((command,payload)) = response.feed(cid,&report)? {
            if command == hid::CMD_ERROR { fail!(EIO,"FIDO_SELECTION_DIAGNOSTIC_HID_ERROR"); }
            return Ok((command,payload));
        }
    }
    Err(err!(ETIMEDOUT,"FIDO_SELECTION_DIAGNOSTIC_FRAME_LIMIT"))
}

#[cfg(all(target_os="macos",feature="macos-hid"))]
static INTERRUPTED: AtomicBool = AtomicBool::new(false);
#[cfg(all(target_os="macos",feature="macos-hid"))]
extern "C" fn interrupt(_:libc::c_int) { INTERRUPTED.store(true,Ordering::SeqCst); }
#[cfg(all(target_os="macos",feature="macos-hid"))]
struct InterruptGuard(libc::sigaction);
#[cfg(all(target_os="macos",feature="macos-hid"))]
impl InterruptGuard {
    fn install()->EnclaveResult<Self> {
        let mut action:libc::sigaction=unsafe {std::mem::zeroed()};
        let mut original:libc::sigaction=unsafe {std::mem::zeroed()};
        action.sa_sigaction=interrupt as *const () as usize;
        if unsafe {libc::sigemptyset(&mut action.sa_mask)}!=0
            || unsafe {libc::sigaction(libc::SIGINT,&action,&mut original)}!=0 {
            fail!(EIO,"FIDO_SELECTION_DIAGNOSTIC_INTERRUPT_SETUP");
        }
        Ok(Self(original))
    }
}
#[cfg(all(target_os="macos",feature="macos-hid"))]
impl Drop for InterruptGuard {fn drop(&mut self) {let _=unsafe {libc::sigaction(libc::SIGINT,&self.0,std::ptr::null_mut())};}}

fn run() -> EnclaveResult<()> { run_with_args(std::env::args().skip(1)) }
fn run_with_args(args: impl IntoIterator<Item = String>) -> EnclaveResult<()> {
    let mut expected = None;
    let mut authorized = false;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--perform-selection-only" if !authorized => authorized = true,
            "--expected-aaguid" if expected.is_none() => {
                let model = args.next().ok_or_else(|| err!(EINVAL, "FIDO_SELECTION_DIAGNOSTIC_ARGUMENT"))?;
                expected = Some(<[u8; 16]>::try_from(hex::decode(model)
                    .map_err(|_| err!(EINVAL, "FIDO_SELECTION_DIAGNOSTIC_ARGUMENT"))?)
                    .map_err(|_| err!(EINVAL, "FIDO_SELECTION_DIAGNOSTIC_ARGUMENT"))?);
            },
            "--help" => {
                println!("enclave-fido-touch-diagnostic --perform-selection-only --expected-aaguid PUBLIC_MODEL_HEX\nEffects: native FIDO enumeration exclusively opens matched HID handles before singleton admission; protocol writes require exactly one device: INIT/GetInfo and one authenticatorSelection(0x0b), requesting physical touch; best-effort same-channel CANCEL only after an interrupted/failed pending selection within the original deadline. No credentials, assertion, PIN, reset, interface or applet changes. Success is selection acknowledgement, not signed UP, enrolled-key identity or D2 custody. No automatic retry; timeout/close does not prove device-side cancellation.");
                return Ok(());
            },
            _ => fail!(EINVAL, "FIDO_SELECTION_DIAGNOSTIC_ARGUMENT"),
        }
    }
    if !authorized { fail!(EPERM, "FIDO_SELECTION_DIAGNOSTIC_EXPLICIT_OPERATION_REQUIRED"); }
    let expected = expected.ok_or_else(|| err!(EINVAL, "FIDO_SELECTION_DIAGNOSTIC_EXPECTED_MODEL_REQUIRED"))?;
    if cfg!(feature = "simulation") || cfg!(feature = "ctap-emulator") {
        fail!(EPERM, "FIDO_SELECTION_DIAGNOSTIC_SIMULATION_BUILD");
    }
    native(&expected)
}

#[cfg(all(target_os = "macos", feature = "macos-hid"))]
fn native(expected: &[u8; 16]) -> EnclaveResult<()> {
    use enclave_custody_vaultd::ctap::macos_hid::MacHidDevice;
    use std::io::Write;
    if unsafe { libc::geteuid() } == 0 { fail!(EPERM, "FIDO_SELECTION_DIAGNOSTIC_UNPRIVILEGED_REQUIRED"); }
    let _interrupt = InterruptGuard::install()?;
    let started = enclave_core::power::continuous_time_ns();
    if started == u64::MAX { fail!(EIO, "FIDO_SELECTION_DIAGNOSTIC_CLOCK"); }
    let boot_end = started.checked_add(10_000_000_000).ok_or_else(|| err!(EIO, "FIDO_SELECTION_DIAGNOSTIC_CLOCK"))?;
    let end = Instant::now() + LIMIT;
    let mut devices = MacHidDevice::enumerate()?;
    if devices.len() != 1 { fail!(EACCES, "FIDO_SELECTION_DIAGNOSTIC_EXACT_ONE_DEVICE_REQUIRED"); }
    let mut native = devices.remove(0);
    native.timeout_s = LIMIT.as_secs_f64();
    let mut device = SelectionDevice::new(native, end, boot_end)?;
    eprintln!("Selection-only diagnostic: touch the YubiKey when it requests touch. No PIN or credential will be used.");
    let _ = std::io::stderr().flush();
    let result = selection_with_cancel(&mut device, expected, &INTERRUPTED);
    if result.is_err() {
        eprintln!("{}",serde_json::json!({"schema":"mcpmac.fido.selection-diagnostic.v1", "status":"CANCELLATION_OBSERVATION",
            "selection_attempted":device.attempted,"cancellation":format!("{:?}",device.cancellation),
            "limits":"CANCEL acknowledgement is protocol status only; no callback quiescence/global cleanup/physical-erasure proof. Never retry automatically."}));
    }
    result?;
    println!("{}", serde_json::json!({
        "schema": "mcpmac.fido.selection-diagnostic.v1", "status": "PASS", "mode": "NATIVE_USER_PHYSICAL_SELECTION",
        "effect": "INIT_GETINFO_AND_SINGLE_SELECTION", "authenticator_selection_completed": true,
        "model_aaguid": hex::encode(expected), "signed_up_verified": false, "enrolled_key_authenticated": false,
        "credential_created": false, "assertion_requested": false, "pin_requested": false,
        "scope": "Physical selection response diagnostic only; no integrated Touch ID-to-YubiKey or custody acceptance",
        "limits": "10s original host deadline includes enumeration and all frames; synchronous native ownership/close/global cleanup and device cancellation remain separately observed or UNKNOWN. No automatic retry."
    }));
    Ok(())
}
#[cfg(not(all(target_os = "macos", feature = "macos-hid")))]
fn native(_: &[u8; 16]) -> EnclaveResult<()> {
    fail!(ENOSYS, "FIDO_SELECTION_DIAGNOSTIC_NATIVE_REQUIRED")
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{}", serde_json::json!({"schema":"mcpmac.fido.selection-diagnostic.v1", "status":"FAIL", "error_code":error.reason,
            "limits":"No automatic replay; a failed or timed-out operation is not proof of device-side cancellation or completed native cleanup."}));
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug, Default)]
    struct Scripted { reports: std::collections::VecDeque<[u8; REPORT]>, writes: Vec<[u8; REPORT]>, version21: bool, status: u8, fail_selection_read: bool, fail_next_read: bool }
    impl HidDevice for Scripted {
        fn write_report(&mut self, report: &[u8; REPORT]) -> EnclaveResult<()> {
            self.writes.push(*report);
            let cid = u32::from_be_bytes(report[..4].try_into().unwrap());
            let (command, payload) = if report[4] == CMD_INIT | 0x80 {
                let mut response = report[7..15].to_vec();response.extend(7u32.to_be_bytes());response.extend([2, 1, 0, 0, 4]);
                (CMD_INIT, response)
            } else if report[7] == 0x04 {
                use ciborium::Value;
                let version = if self.version21 { "FIDO_2_1" } else { "FIDO_2_0" };
                let value = Value::Map(vec![(1.into(), Value::Array(vec![Value::Text(version.into())])), (3.into(), Value::Bytes(vec![7; 16]))]);
                let mut response = vec![0];response.extend(enclave_custody_vaultd::ctap::cbor::encode(&value)?);(CMD_CBOR, response)
            } else if report[4] == (CANCEL | 0x80) { (CMD_CBOR,vec![KEEPALIVE_CANCEL])
            } else { (CMD_CBOR, vec![self.status]) };
            self.reports.extend(hid::packetize(cid, command, &payload)?);
            if report[4] == (CMD_CBOR | 0x80) && report[7] == SELECTION && self.fail_selection_read { self.fail_next_read = true; }
            Ok(())
        }
        fn read_report(&mut self) -> EnclaveResult<[u8; REPORT]> {
            if self.fail_next_read { self.fail_next_read=false;self.reports.pop_front();return Err(err!(EIO,"FIXTURE_SELECTION_READ_FAILED")); }
            self.reports.pop_front().ok_or_else(|| err!(EIO, "FIXTURE_EMPTY"))
        }
        fn hub_depth(&self) -> u8 { 1 }
    }
    fn guarded() -> SelectionDevice<Scripted> {
        SelectionDevice::new(Scripted { version21: true, ..Default::default() }, Instant::now() + LIMIT,
            enclave_core::power::continuous_time_ns() + 10_000_000_000).unwrap()
    }
    fn armed(device:&mut SelectionDevice<Scripted>) {
        CtapClient::open(device).unwrap().get_info().unwrap();
        hid::transact(device,BROADCAST_CID,CMD_INIT,&[8;8]).unwrap();device.arm(7).unwrap();
    }
    #[cfg(any(feature = "simulation", feature = "ctap-emulator"))]
    #[test]
    fn explicit_cli_operation_with_valid_model_refuses_simulation_before_native() {
        let arguments = ["--perform-selection-only", "--expected-aaguid", "07070707070707070707070707070707"];
        let error = run_with_args(arguments.into_iter().map(str::to_owned)).unwrap_err();
        assert!(error.is("FIDO_SELECTION_DIAGNOSTIC_SIMULATION_BUILD"));
    }
    #[test]
    fn guessed_channel_or_nonce_mismatch_cannot_register_a_channel_or_arm_touch() {
        let mut device=guarded();assert!(device.arm(7).is_err());
        assert!(device.write_report(&hid::packetize(7,CMD_CBOR,&[0x04]).unwrap()[0]).is_err());
        device.write_report(&hid::packetize(BROADCAST_CID,CMD_INIT,&[3;8]).unwrap()[0]).unwrap();
        device.inner.reports.front_mut().unwrap()[7]^=1;
        assert!(device.read_report().unwrap_err().is("FIDO_SELECTION_DIAGNOSTIC_INIT_BINDING"));
        assert!(device.allocated.is_none() && device.arm(7).is_err());
        assert_eq!(device.inner.writes.len(),1);
    }
    #[test]
    fn same_channel_cancel_is_single_use_and_never_allows_arbitrary_channel_or_payload() {
        let mut device=guarded();armed(&mut device);
        assert!(device.write_report(&hid::packetize(7,CANCEL,&[]).unwrap()[0]).is_err());
        device.write_report(&hid::packetize(7,CMD_CBOR,&[SELECTION]).unwrap()[0]).unwrap();
        device.inner.reports.clear();
        assert!(device.write_report(&hid::packetize(8,CANCEL,&[]).unwrap()[0]).is_err());
        assert!(device.write_report(&hid::packetize(7,CANCEL,&[1]).unwrap()[0]).is_err());
        device.cancel_pending(7);assert_eq!(device.cancellation,Cancellation::ConfirmedStatus);
        assert!(!device.pending && device.cancel_attempted);
        assert!(device.write_report(&hid::packetize(7,CANCEL,&[]).unwrap()[0]).is_err());
        assert_eq!(device.inner.writes.iter().filter(|r|r[4]==(CANCEL|0x80)).count(),1);
    }
    #[test]
    fn real_pending_read_failure_preserves_original_error_and_sends_one_bounded_cancel_without_replay() {
        let mut device=guarded();device.inner.fail_selection_read=true;
        assert!(selection(&mut device,&[7;16]).unwrap_err().is("FIXTURE_SELECTION_READ_FAILED"));
        assert_eq!(device.cancellation,Cancellation::ConfirmedStatus);
        assert!(device.attempted && device.cancel_attempted && !device.pending);
        assert_eq!(device.inner.writes.iter().filter(|r|r[4]==(CMD_CBOR|0x80)&&r[7]==SELECTION).count(),1);
        assert_eq!(device.inner.writes.iter().filter(|r|r[4]==(CANCEL|0x80)).count(),1);
    }
    #[test]
    fn preexisting_cancellation_has_no_effect_and_expiry_never_extends_the_deadline_to_send_cancel() {
        let mut untouched=guarded();
        assert!(selection_with_cancel(&mut untouched,&[7;16],&AtomicBool::new(true)).unwrap_err().is("FIDO_SELECTION_DIAGNOSTIC_CANCELLED"));
        assert!(untouched.inner.writes.is_empty());
        let mut expired=guarded();armed(&mut expired);
        expired.write_report(&hid::packetize(7,CMD_CBOR,&[SELECTION]).unwrap()[0]).unwrap();
        let before=expired.inner.writes.len();let end=expired.boot_end;expired.end=Instant::now();
        expired.cancel_pending(7);assert_eq!(expired.cancellation,Cancellation::DeadlineUnavailable);
        assert_eq!(expired.boot_end,end);assert_eq!(expired.inner.writes.len(),before);assert!(expired.pending);
    }
    #[test]
    fn actual_virtual_authenticator_selection_touch_and_no_touch_preserve_all_persistent_state() {
        use enclave_custody_vaultd::ctap::virtual_device::{VirtualAuthenticator,Presence};
        for presence in [Presence::Touch,Presence::NoTouch] {
            let mut inner=VirtualAuthenticator::new([7;16]);inner.presence=presence;
            let before=inner.export_state();
            let mut device=SelectionDevice::new(inner,Instant::now()+LIMIT,
                enclave_core::power::continuous_time_ns()+10_000_000_000).unwrap();
            let result=selection(&mut device,&[7;16]);
            match presence {Presence::Touch=>result.unwrap(),Presence::NoTouch=>assert!(result.unwrap_err().is("FIDO_SELECTION_DIAGNOSTIC_TOUCH_TIMEOUT")),_=>unreachable!()}
            assert_eq!(device.inner.export_state(),before);
            assert_eq!(device.inner.assertion_requests,0);assert!(device.attempted && !device.pending);
        }
    }
    #[test]
    fn selection_guard_refuses_every_credential_pin_reset_and_unarmed_selection_report() {
        let mut device = guarded();
        for command in [0x01, 0x02, 0x06, 0x07, 0x08, 0x09, 0x0a, SELECTION, 0x0c] {
            let report = hid::packetize(7, CMD_CBOR, &[command]).unwrap()[0];
            assert!(device.write_report(&report).unwrap_err().is("FIDO_SELECTION_DIAGNOSTIC_OPERATION_FORBIDDEN"));
        }
        let mut continuation = [0; REPORT];continuation[..4].copy_from_slice(&7u32.to_be_bytes());
        assert!(device.write_report(&continuation).is_err());assert!(device.inner.writes.is_empty());
    }
    #[test]
    fn real_client_getinfo_and_exact_one_selection_use_same_handle_without_credential_commands() {
        let mut device = guarded();selection(&mut device, &[7; 16]).unwrap();
        assert_eq!(device.inner.writes.iter().filter(|report| report[4] == (CMD_CBOR | 0x80) && report[7] == SELECTION).count(), 1);
        assert!(device.inner.writes.iter().all(|report| report[4] == (CMD_INIT | 0x80) || (report[4] == (CMD_CBOR | 0x80) && [0x04, SELECTION].contains(&report[7]))));
        let report = hid::packetize(7, CMD_CBOR, &[SELECTION]).unwrap()[0];
        assert!(device.write_report(&report).is_err());assert!(device.arm(7).is_err());
    }
    #[test]
    fn mismatch_or_unsupported_getinfo_cannot_emit_selection_and_unsupported_reply_cannot_fallback() {
        let mut wrong = guarded();assert!(selection(&mut wrong, &[9; 16]).is_err());assert!(!wrong.attempted);
        let mut legacy = guarded();legacy.inner.version21 = false;assert!(selection(&mut legacy, &[7; 16]).unwrap_err().is("FIDO_SELECTION_DIAGNOSTIC_CTAP21_REQUIRED"));assert!(!legacy.attempted);
        let mut unsupported = guarded();unsupported.inner.status = 1;
        assert!(selection(&mut unsupported, &[7; 16]).unwrap_err().is("FIDO_SELECTION_DIAGNOSTIC_UNSUPPORTED"));
        assert_eq!(unsupported.inner.writes.len(), 4);assert!(unsupported.attempted);
    }
    #[test]
    fn exact_channel_padding_and_original_deadline_are_not_replaceable() {
        let mut device = guarded();
        let info = CtapClient::open(&mut device).unwrap().get_info().unwrap(); assert_eq!(info.aaguid,[7;16]);
        let nonce=[8;8]; hid::transact(&mut device,BROADCAST_CID,CMD_INIT,&nonce).unwrap(); device.arm(7).unwrap();
        assert!(device.write_report(&hid::packetize(8, CMD_CBOR, &[SELECTION]).unwrap()[0]).is_err());
        let mut padded = hid::packetize(7, CMD_CBOR, &[SELECTION]).unwrap()[0];padded[8] = 1;
        assert!(device.write_report(&padded).is_err());assert!(!device.attempted);
        assert!(device.set_deadline_ns(None).is_err());assert!(device.set_deadline_ns(Some(device.boot_end + 1)).is_err());
        device.end = Instant::now();assert!(device.write_report(&hid::packetize(7, CMD_CBOR, &[SELECTION]).unwrap()[0]).is_err());
        assert!(!device.attempted && device.inner.writes.len()==3);
    }
}
