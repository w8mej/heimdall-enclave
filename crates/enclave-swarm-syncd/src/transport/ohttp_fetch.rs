//! Profile L3 OHTTP relay client with in-RAM Bao slice verification (FS-702 §4.3, GAP-19).
//!
//! In Profile L3 (`classified-enclave`):
//! 1. All peer listeners and hole punching are strictly disabled (`listen_sockets = 0`).
//!    At startup and prior to fetch, `assert_l3_zero_listeners()` inspects open file descriptors.
//! 2. Target fetches traverse an OHTTP Relay -> OHTTP Gateway pair using HPKE encapsulation.
//! 3. Wire streams carry Bao Merkle trees with 16 KiB leaves over the encrypted ciphertext
//!    (`transport_ciphertext_bao_root`).
//! 4. Every 16 KiB slice is verified in RAM before decryption. Corrupted or poisoned slices
//!    are rejected immediately in RAM, preventing unverified bytes from ever touching APFS.

use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use enclave_crypto::ohttp::{bhttp_post, encapsulate, KeyConfig};

use crate::bao::{self, LEAF_SIZE};
use crate::cas::ContentStore;

/// Verify that this process has no inbound Internet listening/receiving socket.
///
/// TCP listening descriptors and bound, unconnected IPv4/IPv6 UDP receivers
/// are forbidden. Established TCP and kernel-connected UDP clients are not
/// listeners; relay endpoint authentication/egress policy is enforced separately.
/// Unix-domain IPC is unaffected. Required descriptor observations fail closed.
/// This is a point-in-time assertion: callers must not create a listener later.
pub fn assert_l3_zero_listeners() -> EnclaveResult<()> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        for fd in l3_socket_descriptors()? {
            inspect_l3_socket(fd)?;
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fail!(ENOSYS, "KERNEL_FD_QUERY_FAILED", "unsupported descriptor observation platform")
}

#[cfg(target_os = "macos")]
fn l3_socket_descriptors() -> EnclaveResult<Vec<libc::c_int>> {
    let pid = std::process::id() as libc::c_int;
    let item = std::mem::size_of::<libc::proc_fdinfo>();
    let need = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if need <= 0 || need as usize % item != 0 {
        fail!(EIO, "KERNEL_FD_QUERY_FAILED", "invalid descriptor enumeration size: {need}");
    }
    // Bound allocation and leave room for descriptors created during enumeration.
    // Filling the whole buffer is ambiguous (possibly truncated), so reject.
    let count = (need as usize / item).checked_add(32)
        .filter(|count| *count <= 65536)
        .ok_or_else(|| err!(EIO, "KERNEL_FD_QUERY_FAILED", "descriptor enumeration too large"))?;
    let mut entries = Vec::<libc::proc_fdinfo>::with_capacity(count);
    let bytes = count * item;
    let got = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0,
        entries.as_mut_ptr().cast(), bytes as libc::c_int) };
    let used = complete_query_bytes(got, bytes, item)?;
    // The kernel initialized exactly `used / item` complete records.
    unsafe { entries.set_len(used / item); }
    Ok(entries.into_iter().filter(|entry| entry.proc_fdtype == 2)
        .map(|entry| entry.proc_fd).collect())
}

#[cfg(target_os = "linux")]
fn l3_socket_descriptors() -> EnclaveResult<Vec<libc::c_int>> {
    let mut sockets = Vec::new();
    let entries = std::fs::read_dir("/proc/self/fd")
        .map_err(|e| err!(EIO, "KERNEL_FD_QUERY_FAILED", "enumerate descriptors: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| err!(EIO, "KERNEL_FD_QUERY_FAILED", "descriptor entry: {e}"))?;
        let fd = entry.file_name().to_str().and_then(|s| s.parse::<libc::c_int>().ok())
            .ok_or_else(|| err!(EIO, "KERNEL_FD_QUERY_FAILED", "invalid descriptor entry"))?;
        let target = std::fs::read_link(entry.path())
            .map_err(|e| err!(EIO, "KERNEL_FD_QUERY_FAILED", "descriptor link: {e}"))?;
        if target.to_str().is_some_and(|target| target.starts_with("socket:[") && target.ends_with(']')) {
            if sockets.len() >= 65536 {
                fail!(EIO, "KERNEL_FD_QUERY_FAILED", "descriptor enumeration too large");
            }
            sockets.push(fd);
        }
    }
    Ok(sockets)
}

// An exact-capacity result might be a truncated enumeration; non-whole records
// and failed/unsupported queries are never interpreted as an empty socket list.
#[cfg(any(target_os = "macos", test))]
fn complete_query_bytes(got: libc::c_int, capacity: usize, item: usize) -> EnclaveResult<usize> {
    if got <= 0 || got as usize >= capacity || item == 0 || got as usize % item != 0 {
        fail!(EIO, "KERNEL_FD_QUERY_FAILED", "incomplete descriptor enumeration: {got}/{capacity}");
    }
    Ok(got as usize)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn socket_option(fd: libc::c_int, option: libc::c_int) -> EnclaveResult<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    let result = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, option,
        (&mut value as *mut libc::c_int).cast(), &mut length) };
    if result != 0 {
        fail!(EIO, "KERNEL_FD_QUERY_FAILED", "socket option {option}: {}", std::io::Error::last_os_error());
    }
    require_query_length(result, length as usize, std::mem::size_of_val(&value))?;
    Ok(value)
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn require_query_length(result: libc::c_int, got: usize, expected: usize) -> EnclaveResult<()> {
    if result != 0 || got != expected {
        fail!(EIO, "KERNEL_FD_QUERY_FAILED", "failed or short socket query: {result}/{got}/{expected}");
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn inspect_l3_socket(fd: libc::c_int) -> EnclaveResult<()> {
    use std::os::fd::{FromRawFd, AsRawFd, OwnedFd};
    // Pin the descriptor while querying it so a concurrent close/reuse cannot
    // make different queries inspect different sockets. Failure is conservative.
    let pinned = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if pinned < 0 {
        fail!(EIO, "KERNEL_FD_QUERY_FAILED", "cannot pin socket descriptor {fd}");
    }
    let pinned = unsafe { OwnedFd::from_raw_fd(pinned) };
    let fd = pinned.as_raw_fd();
    let kind = socket_option(fd, libc::SO_TYPE)?;
    let mut local: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&local) as libc::socklen_t;
    let result = unsafe { libc::getsockname(fd, (&mut local as *mut libc::sockaddr_storage).cast(), &mut length) };
    if result != 0 || length < 2 || length as usize > std::mem::size_of_val(&local) {
        fail!(EIO, "KERNEL_FD_QUERY_FAILED", "failed or short local socket address");
    }
    let family = local.ss_family as libc::c_int;
    if family != libc::AF_INET && family != libc::AF_INET6 {
        return Ok(()); // The Unix IPC service socket is not an Internet listener.
    }
    let local_port = internet_port(&local, length as usize)?;
    if kind == libc::SOCK_STREAM {
        if tcp_listener(fd)? {
            fail!(EPERM, "L3_LISTENER_FORBIDDEN", "TCP listener on fd {fd}");
        }
    } else if kind == libc::SOCK_DGRAM {
        if local_port != 0 {
            let mut peer: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut peer_length = std::mem::size_of_val(&peer) as libc::socklen_t;
            let result = unsafe { libc::getpeername(fd, (&mut peer as *mut libc::sockaddr_storage).cast(), &mut peer_length) };
            if result != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ENOTCONN) {
                    fail!(EPERM, "L3_LISTENER_FORBIDDEN", "unconnected bound UDP receiver on fd {fd}");
                }
                fail!(EIO, "KERNEL_FD_QUERY_FAILED", "UDP peer query: {error}");
            }
            if peer.ss_family != local.ss_family || internet_port(&peer, peer_length as usize)? == 0 {
                fail!(EIO, "KERNEL_FD_QUERY_FAILED", "invalid connected UDP peer");
            }
        }
    } else {
        fail!(EIO, "KERNEL_FD_QUERY_FAILED", "unsupported Internet socket type {kind}");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn tcp_listener(fd: libc::c_int) -> EnclaveResult<bool> {
    Ok(socket_option(fd, libc::SO_ACCEPTCONN)? != 0)
}

#[cfg(target_os = "macos")]
fn tcp_listener(fd: libc::c_int) -> EnclaveResult<bool> {
    extern "C" {
        fn mcpmac_l3_tcp_listener(fd: libc::c_int, listening: *mut libc::c_int,
            observed: *mut libc::c_int, expected: *mut libc::c_int) -> libc::c_int;
    }
    let (mut listening, mut observed, mut expected) = (0, 0, 0);
    // The SDK-compiled shim queries this process's pinned descriptor and rejects
    // short/unsupported observations. No Rust copy of Darwin structure offsets.
    let result = unsafe { mcpmac_l3_tcp_listener(fd, &mut listening, &mut observed, &mut expected) };
    if result != 0 || observed != expected || expected <= 0 {
        fail!(EIO, "KERNEL_FD_QUERY_FAILED", "Darwin TCP descriptor query {observed}/{expected}: {}", std::io::Error::last_os_error());
    }
    Ok(listening != 0)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn internet_port(address: &libc::sockaddr_storage, length: usize) -> EnclaveResult<u16> {
    match address.ss_family as libc::c_int {
        libc::AF_INET => {
            require_query_length(0, length, std::mem::size_of::<libc::sockaddr_in>())?;
            let address = unsafe { std::ptr::read_unaligned((address as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>()) };
            Ok(u16::from_be(address.sin_port))
        }
        libc::AF_INET6 => {
            require_query_length(0, length, std::mem::size_of::<libc::sockaddr_in6>())?;
            let address = unsafe { std::ptr::read_unaligned((address as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>()) };
            Ok(u16::from_be(address.sin6_port))
        }
        _ => fail!(EIO, "KERNEL_FD_QUERY_FAILED", "unexpected Internet address family"),
    }
}

#[cfg(target_os = "macos")]
const SO_TRAFFIC_CLASS: libc::c_int = 0x1086;
#[cfg(target_os = "macos")]
const SO_TC_BE: libc::c_int = 0;
/// System background traffic class (LEDBAT++).
#[allow(dead_code)]
#[cfg(target_os = "macos")]
pub const SO_TC_BK_SYS: libc::c_int = 100;

/// Derive a 24-byte XChaCha20 nonce for a given slice index, DEK, and Bao root (DEFECT-F-41).
pub fn slice_nonce(root: &[u8; 32], slice_idx: u64) -> [u8; 24] {
    let mut mat = Vec::with_capacity(40);
    mat.extend_from_slice(root);
    mat.extend_from_slice(&slice_idx.to_le_bytes());
    let mut nonce = [0u8; 24];
    let derived = blake3::derive_key("enclave-cas-xchacha-nonce-v2", &mat);
    nonce.copy_from_slice(&derived[..24]);
    nonce
}

/// Encrypt a single 16 KiB slice using XChaCha20Poly1305 with the DEK and root AAD (DEFECT-F-41).
pub fn encrypt_slice(
    dek: &[u8; 32],
    root: &[u8; 32],
    slice_idx: u64,
    plaintext_slice: &[u8],
) -> EnclaveResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(dek));
    let n_bytes = slice_nonce(root, slice_idx);
    let nonce = XNonce::from_slice(&n_bytes);
    let mut aad = Vec::with_capacity(40);
    aad.extend_from_slice(root);
    aad.extend_from_slice(&slice_idx.to_le_bytes());
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext_slice,
                aad: &aad,
            },
        )
        .map_err(|e| err!(EIO, "SLICE_ENCRYPT", "{e}"))
}

/// Decrypt a single 16 KiB slice using XChaCha20Poly1305 with the DEK and root AAD (DEFECT-F-41).
pub fn decrypt_slice(
    dek: &[u8; 32],
    root: &[u8; 32],
    slice_idx: u64,
    ciphertext_slice: &[u8],
) -> EnclaveResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(dek));
    let n_bytes = slice_nonce(root, slice_idx);
    let nonce = XNonce::from_slice(&n_bytes);
    let mut aad = Vec::with_capacity(40);
    aad.extend_from_slice(root);
    aad.extend_from_slice(&slice_idx.to_le_bytes());
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext_slice,
                aad: &aad,
            },
        )
        .map_err(|e| err!(EACCES, "SLICE_DECRYPT", "{e}"))
}

/// Poly1305 authentication tag size.
pub const AEAD_TAG_SIZE: usize = 16;
/// Maximum plaintext slice size so that encrypted slice fits in one 16 KiB Bao leaf.
pub const PLAINTEXT_SLICE_SIZE: usize = LEAF_SIZE - AEAD_TAG_SIZE;

/// Transport artifact package: encrypted ciphertext slices + Bao streaming encoding.
#[derive(Debug)]
pub struct TransportPackage {
    /// Bao root of the ciphertext stream.
    pub transport_ciphertext_bao_root: String,
    /// Total ciphertext length.
    pub ciphertext_len: u64,
    /// Bao streaming stream (parents + ciphertext leaves).
    pub bao_stream: Vec<u8>,
}

/// Package plaintext data into an encrypted, Bao-merkleized transport stream for L2/L3.
pub fn package_transport_artifact(
    plaintext: &[u8],
    dek: &[u8; 32],
) -> EnclaveResult<TransportPackage> {
    let plain_root_hex = bao::bao_root(plaintext);
    let plain_root_bytes =
        hex::decode(&plain_root_hex).map_err(|e| err!(EINVAL, "BAO_ROOT_HEX", "{e}"))?;
    let mut root_arr = [0u8; 32];
    root_arr.copy_from_slice(&plain_root_bytes[..32]);

    let mut ciphertext = Vec::new();
    let mut offset = 0;
    let mut slice_idx = 0u64;

    while offset < plaintext.len() {
        let end = (offset + PLAINTEXT_SLICE_SIZE).min(plaintext.len());
        let slice = &plaintext[offset..end];
        let enc_slice = encrypt_slice(dek, &root_arr, slice_idx, slice)?;
        ciphertext.extend_from_slice(&enc_slice);
        offset = end;
        slice_idx += 1;
    }

    let transport_ciphertext_bao_root = bao::bao_root(&ciphertext);
    let bao_stream = bao::encode_bao_stream(&ciphertext)?;

    Ok(TransportPackage {
        transport_ciphertext_bao_root,
        ciphertext_len: ciphertext.len() as u64,
        bao_stream,
    })
}

/// Verify a streamed transport package in RAM before decrypting.
/// If any slice is corrupted, fails immediately without decrypting or creating any file.
pub fn verify_and_decrypt_stream(
    transport_ciphertext_bao_root: &str,
    ciphertext_len: u64,
    bao_stream: &[u8],
    dek: &[u8; 32],
    expected_plaintext_root: &str,
) -> EnclaveResult<Vec<u8>> {
    let expected_root_bytes =
        hex::decode(expected_plaintext_root).map_err(|e| err!(EINVAL, "EXPECTED_ROOT_HEX", "{e}"))?;
    let mut root_arr = [0u8; 32];
    if expected_root_bytes.len() == 32 {
        root_arr.copy_from_slice(&expected_root_bytes);
    }

    // 1. In-RAM Bao verification: verifies all 16 KiB ciphertext leaves against the transport Bao root.
    // Rejects corrupt/poisoned slices in RAM.
    let verified_ciphertext_slices =
        bao::verify_bao_stream(transport_ciphertext_bao_root, ciphertext_len, bao_stream)?;

    // 2. In-RAM Decryption: decrypts each verified slice.
    let mut plaintext = Vec::new();
    for (idx, slice) in verified_ciphertext_slices.iter().enumerate() {
        let dec = decrypt_slice(dek, &root_arr, idx as u64, slice)?;
        plaintext.extend_from_slice(&dec);
    }

    // 3. In-RAM Plaintext Bao root check against the canonical CAS URI root.
    let computed_plaintext_root = bao::bao_root(&plaintext);
    if computed_plaintext_root != expected_plaintext_root {
        fail!(
            EACCES,
            "CAS_ARTIFACT_DIGEST_MISMATCH",
            "computed {computed_plaintext_root} != expected {expected_plaintext_root}"
        );
    }

    Ok(plaintext)
}

/// Target fetch descriptor for Profile L3 OHTTP.
#[derive(Debug, Clone)]
pub struct L3FetchTarget<'a> {
    /// Target name.
    pub target_name: &'a str,
    /// Expected transport ciphertext Bao root (hex64).
    pub transport_ciphertext_bao_root: &'a str,
    /// Expected logical plaintext Bao root (hex64).
    pub expected_plaintext_root: &'a str,
    /// Data encryption key.
    pub dek: &'a [u8; 32],
}

/// Fetch a target over OHTTP in Profile L3, verify in RAM, and commit to the CAS store.
pub fn fetch_and_commit_l3(
    relay_addr: &str,
    gateway_key: &KeyConfig,
    target: &L3FetchTarget<'_>,
    store: &ContentStore,
) -> EnclaveResult<File> {
    fetch_and_commit_l3_inner(relay_addr, gateway_key, target, store, true)
}

/// Internal fetch with configurable listener check (for in-process mock tests).
pub fn fetch_and_commit_l3_inner(
    relay_addr: &str,
    gateway_key: &KeyConfig,
    target: &L3FetchTarget<'_>,
    store: &ContentStore,
    enforce_zero_listeners: bool,
) -> EnclaveResult<File> {
    // Enforce L3 zero-listeners assertion before network fetch
    if enforce_zero_listeners {
        assert_l3_zero_listeners()?;
    }

    // 1. Build BHTTP request
    let bhttp_req = bhttp_post(
        "cas.gateway.internal",
        &format!(
            "/v1/cas/fetch?target={}&root={}",
            target.target_name, target.transport_ciphertext_bao_root
        ),
        "application/json",
        b"",
    );

    // 2. Encapsulate with Gateway public key
    let enc_req = encapsulate(gateway_key, &bhttp_req)?;

    // 3. Connect to OHTTP Relay over TCP
    let mut stream =
        TcpStream::connect(relay_addr).map_err(|e| err!(EIO, "RELAY_CONNECT", "{e}"))?;

    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        let traffic_class: libc::c_int = SO_TC_BE;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_TRAFFIC_CLASS,
                &traffic_class as *const _ as *const libc::c_void,
                std::mem::size_of_val(&traffic_class) as libc::socklen_t,
            );
        }
    }

    // HTTP POST to relay
    let http_req = format!(
        "POST /relay HTTP/1.1\r\nHost: {relay_addr}\r\nContent-Type: message/ohttp-req\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        enc_req.len()
    );
    stream
        .write_all(http_req.as_bytes())
        .map_err(|e| err!(EIO, "RELAY_WRITE", "{e}"))?;
    stream
        .write_all(&enc_req)
        .map_err(|e| err!(EIO, "RELAY_WRITE", "{e}"))?;
    stream
        .flush()
        .map_err(|e| err!(EIO, "RELAY_FLUSH", "{e}"))?;

    // Read response from relay
    let mut resp_bytes = Vec::new();
    stream
        .read_to_end(&mut resp_bytes)
        .map_err(|e| err!(EIO, "RELAY_READ", "{e}"))?;

    // Parse HTTP response header
    let header_sep = b"\r\n\r\n";
    let sep_pos = resp_bytes
        .windows(4)
        .position(|w| w == header_sep)
        .ok_or_else(|| err!(EIO, "RELAY_RESPONSE_FORMAT", "no HTTP header separator"))?;
    let header_str = String::from_utf8_lossy(&resp_bytes[..sep_pos]);
    if !header_str.starts_with("HTTP/1.1 200") && !header_str.starts_with("HTTP/1.0 200") {
        fail!(EIO, "RELAY_ERROR", "HTTP status not 200: {header_str}");
    }
    let body = &resp_bytes[sep_pos + 4..];

    // Body format: [8-byte big-endian ciphertext_len] [bao_stream bytes]
    if body.len() < 8 {
        fail!(EIO, "RELAY_RESPONSE_TRUNCATED");
    }
    let ciphertext_len = u64::from_be_bytes(body[..8].try_into().unwrap());
    let bao_stream = &body[8..];

    // 4. Verify in RAM & decrypt (never writes partial/corrupted bytes to disk)
    let plaintext = verify_and_decrypt_stream(
        target.transport_ciphertext_bao_root,
        ciphertext_len,
        bao_stream,
        target.dek,
        target.expected_plaintext_root,
    )?;

    // 5. Store in CAS atomically and return read-only FD
    let m = store.put(&plaintext)?;
    if m.blake3 != target.expected_plaintext_root {
        fail!(EACCES, "CAS_ARTIFACT_DIGEST_MISMATCH");
    }

    store.open_readonly(target.expected_plaintext_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclave_crypto::ohttp::{bhttp_parse, decapsulate};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;

    static TEST_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn l3_guard_required_observations_fail_closed() {
        // These exercise the same result validators and real query path used
        // by production, not a duplicate listener-classification predicate.
        for (got, cap, item) in [(-1, 32, 8), (0, 32, 8), (7, 32, 8), (32, 32, 8), (40, 32, 8)] {
            assert_eq!(complete_query_bytes(got, cap, item).unwrap_err().reason, "KERNEL_FD_QUERY_FAILED");
        }
        assert_eq!(complete_query_bytes(16, 32, 8).unwrap(), 16);
        for (result, length) in [(-1, 4), (0, 0), (0, 3), (0, 8)] {
            assert_eq!(require_query_length(result, length, 4).unwrap_err().reason, "KERNEL_FD_QUERY_FAILED");
        }
        require_query_length(0, 4, 4).unwrap();
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        assert_eq!(inspect_l3_socket(-1).unwrap_err().reason, "KERNEL_FD_QUERY_FAILED");
    }

    #[test]
    fn test_zero_listeners_assertion() {
        let _guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        // Initially no listening socket: should pass
        assert_l3_zero_listeners().expect("zero listeners initially");

        // Bind a listening socket: should fail
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let res = assert_l3_zero_listeners();
        assert!(res.is_err(), "listening socket must be detected");
        assert!(format!("{:?}", res.err().unwrap()).contains("L3_LISTENER_FORBIDDEN"));

        // Drop listener: should pass again
        drop(listener);
        assert_l3_zero_listeners().expect("zero listeners after drop");
    }

    #[test]
    fn test_slice_encrypt_decrypt_roundtrip() {
        let dek = [0x55u8; 32];
        let root = [0x77u8; 32];
        let plaintext = b"Hello secret model slice in Profile L3";
        let enc = encrypt_slice(&dek, &root, 0, plaintext).expect("encrypt");
        let dec = decrypt_slice(&dek, &root, 0, &enc).expect("decrypt");
        assert_eq!(dec, plaintext);

        // Tamper with ciphertext
        let mut tampered = enc.clone();
        *tampered.last_mut().unwrap() ^= 0x01;
        assert!(decrypt_slice(&dek, &root, 0, &tampered).is_err());

        // Wrong root fails decryption
        let wrong_root = [0x88u8; 32];
        assert!(decrypt_slice(&dek, &wrong_root, 0, &enc).is_err());
    }

    #[test]
    fn test_package_and_verify_clean() {
        let dek = [0x77u8; 32];
        let plaintext = vec![0xa5u8; 45 * 1024]; // 45 KiB = 3 slices
        let plain_root = bao::bao_root(&plaintext);

        let pkg = package_transport_artifact(&plaintext, &dek).expect("package");
        assert_eq!(pkg.transport_ciphertext_bao_root.len(), 64);

        let decrypted = verify_and_decrypt_stream(
            &pkg.transport_ciphertext_bao_root,
            pkg.ciphertext_len,
            &pkg.bao_stream,
            &dek,
            &plain_root,
        )
        .expect("verify and decrypt");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_midstream_poisoning_rejected_in_ram() {
        let dek = [0x88u8; 32];
        // 64 KiB = 4 slices of 16 KiB
        let plaintext = vec![0x11u8; 64 * 1024];
        let plain_root = bao::bao_root(&plaintext);

        let pkg = package_transport_artifact(&plaintext, &dek).expect("package");

        // Poison byte in slice 2
        let mut poisoned_stream = pkg.bao_stream.clone();
        let mid = poisoned_stream.len() / 2;
        poisoned_stream[mid] ^= 0xff;

        let res = verify_and_decrypt_stream(
            &pkg.transport_ciphertext_bao_root,
            pkg.ciphertext_len,
            &poisoned_stream,
            &dek,
            &plain_root,
        );

        assert!(res.is_err(), "poisoned slice must be rejected");
        let err_str = format!("{:?}", res.err().unwrap());
        assert!(err_str.contains("BAO_SLICE_CORRUPT"));
    }

    #[test]
    fn test_truncated_stream_rejected() {
        let dek = [0x99u8; 32];
        let plaintext = vec![0x22u8; 32 * 1024];
        let plain_root = bao::bao_root(&plaintext);

        let pkg = package_transport_artifact(&plaintext, &dek).expect("package");
        let truncated = &pkg.bao_stream[..pkg.bao_stream.len() / 2];

        let res = verify_and_decrypt_stream(
            &pkg.transport_ciphertext_bao_root,
            pkg.ciphertext_len,
            truncated,
            &dek,
            &plain_root,
        );

        assert!(res.is_err(), "truncated stream must be rejected");
    }

    #[test]
    fn test_end_to_end_ohttp_relay_fetch() {
        let _guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let temp_dir =
            std::env::temp_dir().join(format!("cas_l3_test_{}", enclave_core::rng::u64()));
        let store = ContentStore::open(&temp_dir).expect("store");

        let dek = [0x33u8; 32];
        let plaintext = vec![0xeeu8; 50 * 1024];
        let plain_root = bao::bao_root(&plaintext);
        let target_name = "test-l3-weights.safetensors";

        let pkg = package_transport_artifact(&plaintext, &dek).expect("package");
        let pkg_len = pkg.ciphertext_len;
        let pkg_stream = pkg.bao_stream.clone();

        // Gateway keypair
        let (gw_key, gw_sk) = enclave_crypto::ohttp::gateway_keypair(1);

        // Start mock in-process Relay + Gateway server on loopback
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock relay");
        let relay_addr = listener.local_addr().expect("local addr").to_string();
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        let handle = thread::spawn(move || {
            while running_clone.load(Ordering::SeqCst) {
                listener.set_nonblocking(true).unwrap();
                match listener.accept() {
                    Ok((mut sock, _)) => {
                        sock.set_nonblocking(false).unwrap();
                        sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                            .unwrap();
                        let mut buf = vec![0u8; 16 * 1024];
                        let mut n = 0;
                        while !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                            let read_bytes = match sock.read(&mut buf[n..]) {
                                Ok(0) => break,
                                Ok(k) => k,
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    thread::sleep(std::time::Duration::from_millis(5));
                                    continue;
                                }
                                Err(e) => panic!("sock read error: {e}"),
                            };
                            n += read_bytes;
                        }
                        let req_bytes = &buf[..n];

                        // Extract encapsulated body after \r\n\r\n
                        let sep_pos = req_bytes
                            .windows(4)
                            .position(|w| w == b"\r\n\r\n")
                            .expect("sep");
                        let enc_req = &req_bytes[sep_pos + 4..];

                        // Decapsulate at Gateway
                        let (path, _) =
                            bhttp_parse(&decapsulate(1, &gw_sk, enc_req).unwrap()).unwrap();
                        assert!(path.contains(target_name));

                        // Build response body: [8-byte ciphertext_len] [bao_stream]
                        let mut body = pkg_len.to_be_bytes().to_vec();
                        body.extend_from_slice(&pkg_stream);

                        let http_resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        sock.write_all(http_resp.as_bytes()).unwrap();
                        sock.write_all(&body).unwrap();
                        sock.flush().unwrap();
                        break;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            }
        });

        // Run client fetch (disable same-process listener assertion for loopback test)
        let target = L3FetchTarget {
            target_name,
            transport_ciphertext_bao_root: &pkg.transport_ciphertext_bao_root,
            expected_plaintext_root: &plain_root,
            dek: &dek,
        };
        let file = fetch_and_commit_l3_inner(&relay_addr, &gw_key, &target, &store, false)
            .expect("fetch and commit");

        assert!(file.metadata().is_ok());
        assert!(store.contains(&plain_root));

        let retrieved = store.get(&plain_root).expect("cas get");
        assert_eq!(retrieved, plaintext);

        running.store(false, Ordering::SeqCst);
        let _ = handle.join();
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_end_to_end_poisoned_fetch_creates_no_file() {
        let _guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let temp_dir =
            std::env::temp_dir().join(format!("cas_l3_poison_test_{}", enclave_core::rng::u64()));
        let store = ContentStore::open(&temp_dir).expect("store");

        let dek = [0x44u8; 32];
        let plaintext = vec![0x12u8; 40 * 1024];
        let plain_root = bao::bao_root(&plaintext);
        let target_name = "poisoned-model.safetensors";

        let pkg = package_transport_artifact(&plaintext, &dek).expect("package");
        let pkg_len = pkg.ciphertext_len;
        let mut poisoned_stream = pkg.bao_stream.clone();
        // Corrupt a byte in slice 1
        let mid = poisoned_stream.len() / 2;
        poisoned_stream[mid] ^= 0xff;

        let (gw_key, gw_sk) = enclave_crypto::ohttp::gateway_keypair(2);

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock relay");
        let relay_addr = listener.local_addr().expect("local addr").to_string();
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        let handle = thread::spawn(move || {
            while running_clone.load(Ordering::SeqCst) {
                listener.set_nonblocking(true).unwrap();
                match listener.accept() {
                    Ok((mut sock, _)) => {
                        sock.set_nonblocking(false).unwrap();
                        sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                            .unwrap();
                        let mut buf = vec![0u8; 16 * 1024];
                        let mut n = 0;
                        while !buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                            let read_bytes = match sock.read(&mut buf[n..]) {
                                Ok(0) => break,
                                Ok(k) => k,
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    thread::sleep(std::time::Duration::from_millis(5));
                                    continue;
                                }
                                Err(e) => panic!("sock read error: {e}"),
                            };
                            n += read_bytes;
                        }
                        let req_bytes = &buf[..n];

                        let sep_pos = req_bytes
                            .windows(4)
                            .position(|w| w == b"\r\n\r\n")
                            .expect("sep");
                        let enc_req = &req_bytes[sep_pos + 4..];

                        let (path, _) =
                            bhttp_parse(&decapsulate(2, &gw_sk, enc_req).unwrap()).unwrap();
                        assert!(path.contains(target_name));

                        let mut body = pkg_len.to_be_bytes().to_vec();
                        body.extend_from_slice(&poisoned_stream);

                        let http_resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        sock.write_all(http_resp.as_bytes()).unwrap();
                        sock.write_all(&body).unwrap();
                        sock.flush().unwrap();
                        break;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            }
        });

        let target = L3FetchTarget {
            target_name,
            transport_ciphertext_bao_root: &pkg.transport_ciphertext_bao_root,
            expected_plaintext_root: &plain_root,
            dek: &dek,
        };
        let res = fetch_and_commit_l3_inner(&relay_addr, &gw_key, &target, &store, false);

        assert!(res.is_err(), "poisoned fetch must fail");
        let err_str = format!("{:?}", res.err().unwrap());
        assert!(err_str.contains("BAO_SLICE_CORRUPT"));

        // Crucial verification: assert no file created on disk / in CAS
        assert!(
            !store.contains(&plain_root),
            "store must not contain poisoned artifact"
        );
        let objects_dir = temp_dir.join("objects");
        assert!(
            !objects_dir.exists() || !objects_dir.join(&plain_root).exists(),
            "objects must not contain file"
        );
        let chunks_dir = temp_dir.join("chunks");
        assert!(
            std::fs::read_dir(&chunks_dir).unwrap().next().is_none(),
            "no chunks must be committed on failure"
        );

        running.store(false, Ordering::SeqCst);
        let _ = handle.join();
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
