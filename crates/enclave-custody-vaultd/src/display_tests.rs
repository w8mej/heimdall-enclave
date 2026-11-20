use super::*;
use std::{os::unix::net::UnixStream, time::Duration};

#[test]
fn native_display_acknowledges_once_and_revokes_without_ceremony_lock() {
    for wrong_nonce in [false, true] {
        let (client, mut helper) = UnixStream::pair().unwrap();
        let mut display = NativeHelperDisplay::new("/unused-fixture".into());
        *display.revocation.lock().unwrap() = Some(client.try_clone().unwrap());
        display.stream = Some(client);
        display.nonce = Some([7; 32]);
        let revoke = display.revocation_handle().unwrap();
        let worker = std::thread::spawn(move || {
            helper
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut length = [0; 4];
            helper.read_exact(&mut length).unwrap();
            let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
            helper.read_exact(&mut bytes).unwrap();
            assert_eq!(
                bytes,
                [0x81, 0x49, b's', b'y', b'n', b't', b'h', b'e', b't', b'i', b'c']
            );
            let mut ack = SHOWN.to_vec();
            ack.extend_from_slice(&[if wrong_nonce { 8 } else { 7 }; 32]);
            helper.write_all(&(ack.len() as u32).to_be_bytes()).unwrap();
            helper.write_all(&ack).unwrap();
            assert_eq!(
                helper.read(&mut [0]).unwrap(),
                0,
                "all original/control handles shut down on revocation or unconfirmed ACK"
            );
        });
        let result = display.show_prepared(
            &[],
            &[
                0x81, 0x49, b's', b'y', b'n', b't', b'h', b'e', b't', b'i', b'c',
            ],
        );
        if wrong_nonce {
            assert!(result.unwrap_err().is("DISPLAY_ACK_PROTOCOL"));
            assert!(display.stream.is_none());
        } else {
            result.unwrap();
            assert!(
                display.nonce.is_none(),
                "one preparation cannot release twice"
            );
            // The display object remains borrowed/owned by its ceremony. Its
            // independent control still revokes without acquiring that lock.
            revoke().unwrap();
        }
        worker.join().unwrap();
    }
}

#[test]
fn native_display_original_critical_deadline_prevents_any_late_bytes() {
    let (client, mut helper) = UnixStream::pair().unwrap();
    let mut display = NativeHelperDisplay::new("/unused-fixture".into());
    *display.revocation.lock().unwrap() = Some(client.try_clone().unwrap());
    display.stream = Some(client);
    display.nonce = Some([7; 32]);
    display.ceremony_deadline = Some(enclave_core::clock::boot_clock_ns().saturating_sub(1));
    assert!(display
        .show_prepared(&[], &[0x81, 0x40])
        .unwrap_err()
        .is("DISPLAY_RELEASE_UNCERTAIN"));
    helper
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    assert_eq!(helper.read(&mut [0]).unwrap(), 0);
}
