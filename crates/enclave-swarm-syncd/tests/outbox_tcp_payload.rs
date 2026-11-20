//! Logical payload bounds, with no dense allocation of the maximum payload.
use enclave_swarm_syncd::outbox::{OutboxTransport, TcpOutboxTransport, DEFAULT_MAX_OUTBOX_BYTES};

#[test]
fn tcp_oversize_payload_refuses_before_connect_without_touching_mapping() {
    struct Mapping(*mut libc::c_void, usize);
    impl Drop for Mapping {
        fn drop(&mut self) { assert_eq!(unsafe { libc::munmap(self.0, self.1) }, 0); }
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let length = usize::try_from(DEFAULT_MAX_OUTBOX_BYTES).unwrap() + 1;
    // A real read-only demand-zero mapping supplies a valid borrowed slice.
    // Product checks length only; no pages are touched/copied by this test.
    let raw = unsafe { libc::mmap(std::ptr::null_mut(), length, libc::PROT_READ,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0) };
    assert_ne!(raw, libc::MAP_FAILED);
    let mapping = Mapping(raw, length);
    assert!(!mapping.0.is_null(), "Rust borrowed slices require a non-null mapping");
    let payload = unsafe { std::slice::from_raw_parts(mapping.0.cast::<u8>(), mapping.1) };
    let result = TcpOutboxTransport::new(listener.local_addr().unwrap(), "owned.invalid").transmit(payload);
    assert!(result.unwrap_err().is("GATEWAY_PAYLOAD_TOO_LARGE"));
    assert_eq!(listener.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
}
