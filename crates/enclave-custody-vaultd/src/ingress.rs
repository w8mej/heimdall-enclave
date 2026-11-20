//! Ingress commitment and witness emission for UID 703 (GAP-10).
//!
//! At ingress (`Tokenize` and `ScrubText`), UID 703 computes:
//! - `C_raw = Poseidon2(b"depot-C_raw-v1" ‖ D_raw ‖ b"depot-C_raw-blind-v1" ‖ r_raw)`
//!   with fresh blinding scalar `r_raw` zeroized immediately;
//! - `H_ingress_mac = Poseidon2(b"depot-IngressMac-v1" ‖ K_ingress ‖ seq ‖ C_raw)`;
//! - keeps `(slot, D_scrub, C_raw, H_ingress_mac)` in a bounded ring and streams
//!   it to UID 705 over the dedicated 703→705 witness socket.

use std::path::Path;

use enclave_core::daemon::{DaemonId, WITNESS_SOCKET_NAME};
use enclave_core::error::EnclaveResult;
use enclave_core::ipc::{Client, FrameIoLimits, ServeLimits};
use enclave_core::poseidon2::{Poseidon2Digest, Poseidon2Sponge};
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Wire request on the dedicated 703→705 witness socket (GAP-10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WitnessChannelRequest {
    /// Stream one or more witness folds to UID 705.
    StreamWitness {
        /// Epoch ID.
        boot_epoch_id: String,
        /// Folds.
        folds: Vec<WitnessFold>,
    },
    /// Query witnesses from UID 705.
    FetchWitness {
        /// Epoch ID.
        boot_epoch_id: String,
        /// Start slot.
        s_start: u64,
        /// End slot.
        s_end: u64,
    },
}

/// Wire response on the dedicated 703→705 witness socket (GAP-10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WitnessChannelResponse {
    /// Acknowledged.
    Ack,
    /// Returned witnesses.
    Witness {
        /// Folds.
        folds: Vec<WitnessFold>,
        /// Next slot.
        next_slot: u64,
    },
}

/// One released vault slot witness fold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessFold {
    /// Sequence / slot number.
    pub rpc_seq_u64: u64,
    /// Scrubbed text bytes.
    #[serde(with = "serde_bytes")]
    pub scrubbed: Vec<u8>,
    /// Commitment `C_raw` (hex).
    pub c_raw: String,
    /// Ingress MAC `H_ingress_mac` (hex).
    pub h_ingress_mac: String,
}

/// Compute commitment `C_raw = Poseidon2(b"depot-C_raw-v1" ‖ raw ‖ b"depot-C_raw-blind-v1" ‖ r_raw)`.
pub fn compute_c_raw(raw: &[u8], r_raw: &[u8; 32]) -> Poseidon2Digest {
    let mut c = Poseidon2Sponge::new();
    c.absorb_bytes(b"depot-C_raw-v1", raw);
    c.absorb_bytes(b"depot-C_raw-blind-v1", r_raw);
    c.finalize()
}

/// Compute ingress MAC `H_ingress_mac = Poseidon2(b"depot-IngressMac-v1" ‖ ingress_key ‖ seq ‖ C_raw)`.
pub fn compute_ingress_mac(
    ingress_key: &[u8; 32],
    seq: u64,
    c_raw: &Poseidon2Digest,
) -> Poseidon2Digest {
    let mut h = Poseidon2Sponge::new();
    h.absorb_bytes(b"depot-IngressMac-v1", ingress_key);
    h.absorb_u64(seq);
    for l in c_raw.0 {
        h.absorb_u32(l);
    }
    h.finalize()
}

/// Build a `WitnessFold` from raw ingress data and scrubbed output, generating fresh blinding.
pub fn create_witness_fold(
    ingress_key: &[u8; 32],
    seq: u64,
    raw: &[u8],
    scrubbed: Vec<u8>,
) -> WitnessFold {
    let mut r = [0u8; 32];
    enclave_core::rng::fill(&mut r);
    let c_raw = compute_c_raw(raw, &r);
    r.zeroize();
    let h_mac = compute_ingress_mac(ingress_key, seq, &c_raw);
    WitnessFold {
        rpc_seq_u64: seq,
        scrubbed,
        c_raw: c_raw.to_hex(),
        h_ingress_mac: h_mac.to_hex(),
    }
}

#[derive(Serialize)]
enum BorrowedWitnessRequest<'a> {
    StreamWitness { boot_epoch_id: &'a str, folds: &'a [WitnessFold] },
}

// Count before reserving output. All output is wrapped before sensitive writes;
// populated storage never reallocates. This bounds requested encoding storage,
// not caller-owned inputs, allocator overhead or physical process memory.
struct CappedCborWriter {
    body: Option<zeroize::Zeroizing<Vec<u8>>>,
    written: usize,
    limit: usize,
    exceeded: bool,
}

impl std::io::Write for CappedCborWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end = self.written.checked_add(bytes.len()).filter(|end| *end <= self.limit);
        let Some(end) = end else {
            self.exceeded = true;
            return Err(std::io::Error::from(std::io::ErrorKind::FileTooLarge));
        };
        if let Some(body) = self.body.as_mut() {
            if end > body.capacity() {
                return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
            }
            body.extend_from_slice(bytes);
        }
        self.written = end;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

fn encode_witness_bounded<T: Serialize>(request: &T, limit: usize) -> EnclaveResult<zeroize::Zeroizing<Vec<u8>>> {
    let mut counter = CappedCborWriter { body: None, written: 0, limit, exceeded: false };
    let counted = ciborium::into_writer(request, &mut counter);
    if counter.exceeded { fail!(E2BIG, "WITNESS_FRAME_TOO_LARGE"); }
    if counted.is_err() { fail!(EINVAL, "WITNESS_ENCODE"); }
    let mut body = zeroize::Zeroizing::new(Vec::new());
    body.try_reserve_exact(counter.written).map_err(|_| err!(ENOMEM, "WITNESS_ENCODE_ALLOC"))?;
    let mut writer = CappedCborWriter { body: Some(body), written: 0, limit: counter.written, exceeded: false };
    let encoded = ciborium::into_writer(request, &mut writer);
    if writer.exceeded { fail!(E2BIG, "WITNESS_FRAME_TOO_LARGE"); }
    if encoded.is_err() || writer.written != counter.written { fail!(EINVAL, "WITNESS_ENCODE"); }
    writer.body.take().ok_or_else(|| err!(EINVAL, "WITNESS_ENCODE"))
}

/// Client for streaming witness folds to UID 705 over the dedicated witness socket.
#[derive(Debug)]
pub struct WitnessStreamClient;

impl WitnessStreamClient {
    /// Stream a batch of witness folds to UID 705 over the dedicated socket.
    pub fn stream(
        socket_dir: &Path,
        boot_epoch_id: &str,
        folds: Vec<WitnessFold>,
    ) -> EnclaveResult<()> {
        Self::stream_with_mode(socket_dir, boot_epoch_id, folds, false)
    }

    /// Explicit trusted same-UID development mode. Production callers retain
    /// the strict default; paths, profiles and observed UIDs never enable it.
    pub fn stream_with_mode(
        socket_dir: &Path,
        boot_epoch_id: &str,
        folds: Vec<WitnessFold>,
        dev_same_uid: bool,
    ) -> EnclaveResult<()> {
        Self::stream_borrowed_with_mode(socket_dir, boot_epoch_id, &folds, dev_same_uid)
    }

    // Synchronous borrow only: the caller retains its folds throughout the
    // existing authenticated exchange. Public owned entry points stay intact.
    pub(crate) fn stream_borrowed_with_mode(
        socket_dir: &Path,
        boot_epoch_id: &str,
        folds: &[WitnessFold],
        dev_same_uid: bool,
    ) -> EnclaveResult<()> {
        let sock_path = socket_dir.join(WITNESS_SOCKET_NAME);
        if !sock_path.exists() {
            // If the listener is not running, streaming is best-effort;
            // 705 can also fetch or read if configured.
            return Ok(());
        }
        let code = (!dev_same_uid).then(|| enclave_core::codesign::CodeRequirement::daemon(DaemonId::ZkAuditor));
        let frame_io = FrameIoLimits::witness();
        let client = Client::connect_verified_deadline(
            &sock_path,
            if dev_same_uid { enclave_core::ipc::geteuid() } else { DaemonId::ZkAuditor.uid() },
            code.as_ref(),
            frame_io.frame_deadline,
        )?;
        let req = BorrowedWitnessRequest::StreamWitness {
            boot_epoch_id,
            folds,
        };
        let limits = ServeLimits::for_daemon(DaemonId::ZkAuditor, false);
        let body = encode_witness_bounded(&req, limits.max_frame)?;
        let resp_bytes = client.exchange_preencoded(&body, &frame_io)?;
        let resp: WitnessChannelResponse = ciborium::from_reader(resp_bytes.as_slice())
            .map_err(|e| err!(EINVAL, "WITNESS_DECODE", "{e}"))?;
        match resp {
            WitnessChannelResponse::Ack => Ok(()),
            _ => fail!(EIO, "WITNESS_UNEXPECTED_RESP"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_fold_computation_deterministic() {
        let key = [42u8; 32];
        let seq = 100;
        let raw = b"secret data 1234";
        let r = [1u8; 32];
        let c1 = compute_c_raw(raw, &r);
        let c2 = compute_c_raw(raw, &r);
        assert_eq!(c1, c2);
        let m1 = compute_ingress_mac(&key, seq, &c1);
        let m2 = compute_ingress_mac(&key, seq, &c1);
        assert_eq!(m1, m2);
    }

    #[test]
    fn witness_fold_blinding_changes_digest() {
        let key = [42u8; 32];
        let w1 = create_witness_fold(&key, 1, b"hello", b"h***o".to_vec());
        let w2 = create_witness_fold(&key, 1, b"hello", b"h***o".to_vec());
        assert_ne!(w1.c_raw, w2.c_raw);
        assert_ne!(w1.h_ingress_mac, w2.h_ingress_mac);
        assert_eq!(w1.c_raw.len(), 64);
        assert_eq!(w1.h_ingress_mac.len(), 64);
    }
    #[test]
    fn bounded_encoding_preserves_owned_request_wire() {
        let folds = vec![WitnessFold { rpc_seq_u64: 1, scrubbed: b"safe".to_vec(), c_raw: "abc".into(), h_ingress_mac: "def".into() }];
        let owned = WitnessChannelRequest::StreamWitness { boot_epoch_id: "epoch".into(), folds: folds.clone() };
        let mut reference = Vec::new();
        ciborium::into_writer(&owned, &mut reference).unwrap();
        let borrowed = BorrowedWitnessRequest::StreamWitness { boot_epoch_id: "epoch", folds: &folds };
        let actual = encode_witness_bounded(&borrowed, reference.len()).unwrap();
        assert!(actual.as_slice() == reference.as_slice());
        assert!(encode_witness_bounded(&borrowed, reference.len() - 1).unwrap_err().is("WITNESS_FRAME_TOO_LARGE"));
    }

    #[test]
    fn bounded_writer_exact_cap_and_refusal_never_mutate_or_reallocate_output() {
        use std::io::Write;
        let mut body = zeroize::Zeroizing::new(Vec::new());
        body.try_reserve_exact(8).unwrap();
        let capacity = body.capacity();
        let mut writer = CappedCborWriter { body: Some(body), written: 0, limit: 8, exceeded: false };
        writer.write_all(b"123").unwrap();
        writer.write_all(b"45678").unwrap();
        assert_eq!(writer.written, 8);
        assert_eq!(writer.body.as_ref().unwrap().capacity(), capacity);
        assert!(writer.write_all(b"9").is_err());
        assert!(writer.exceeded);
        assert_eq!(writer.written, 8);
        assert_eq!(writer.body.as_ref().unwrap().as_slice(), b"12345678");
        assert_eq!(writer.body.as_ref().unwrap().capacity(), capacity);
    }

    #[test]
    fn bounded_counter_checked_overflow_and_zero_limit_refuse_without_wrap() {
        use std::io::Write;
        let mut counter = CappedCborWriter { body: None, written: usize::MAX, limit: usize::MAX, exceeded: false };
        assert!(counter.write(b"x").is_err());
        assert!(counter.exceeded);
        assert_eq!(counter.written, usize::MAX);
        assert!(encode_witness_bounded(&(), 0).unwrap_err().is("WITNESS_FRAME_TOO_LARGE"));
    }

    struct ChangingSize { passes: std::cell::Cell<usize>, grow: bool }
    impl Serialize for ChangingSize {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let pass = self.passes.get();
            self.passes.set(pass + 1);
            serializer.serialize_str(if (pass == 0) == self.grow { "a" } else { "bigger" })
        }
    }

    #[test]
    fn bounded_encoding_stateful_second_pass_growth_and_shrink_fail_closed() {
        let grows = ChangingSize { passes: std::cell::Cell::new(0), grow: true };
        assert!(encode_witness_bounded(&grows, 64).unwrap_err().is("WITNESS_FRAME_TOO_LARGE"));
        let shrinks = ChangingSize { passes: std::cell::Cell::new(0), grow: false };
        assert!(encode_witness_bounded(&shrinks, 64).unwrap_err().is("WITNESS_ENCODE"));
    }

    struct SwallowsWriteError;
    impl Serialize for SwallowsWriteError {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeSeq;
            let mut seq = serializer.serialize_seq(Some(1))?;
            let _ = seq.serialize_element(&"x".repeat(128));
            seq.end()
        }
    }

    #[test]
    fn bounded_encoding_sticky_overflow_refuses_a_swallowed_write_error() {
        assert!(encode_witness_bounded(&SwallowsWriteError, 16).unwrap_err().is("WITNESS_FRAME_TOO_LARGE"));
    }

    struct FailsWithPrivateDetail;
    impl Serialize for FailsWithPrivateDetail {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("private-test-sentinel"))
        }
    }

    #[test]
    fn bounded_encoding_sanitizes_custom_serializer_error() {
        let error = encode_witness_bounded(&FailsWithPrivateDetail, 64).unwrap_err();
        assert!(error.is("WITNESS_ENCODE"));
        assert!(error.detail.is_empty());
    }

}
