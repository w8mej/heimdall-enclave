//! Integration tests for L3 pre-egress pi_redact gate and tool egress proxy (GAP-25, FS-705 §4.3.1).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use ed25519_dalek::SigningKey;
use enclave_core::err;
use enclave_core::error::EnclaveResult;
use enclave_tool_host::proxy::{EgressGateClient, ToolEgressProxy};
use enclave_zk_auditor::zk::redact::{evaluate_and_prove_chunk, RedactProofV1, MAX_CHUNK_SIZE};

/// Test mock gate client backed by in-memory redaction engine.
struct LocalRedactGateClient {
    sk: SigningKey,
    calls: AtomicUsize,
}

impl LocalRedactGateClient {
    fn new(sk: SigningKey) -> Self {
        Self {
            sk,
            calls: AtomicUsize::new(0),
        }
    }
}

impl EgressGateClient for LocalRedactGateClient {
    fn gate_chunk(&self, d_jcs: &[u8], chunk: &[u8]) -> EnclaveResult<RedactProofV1> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let ts_ns = 1_700_000_000_000_000_000;
        evaluate_and_prove_chunk(&self.sk, d_jcs, chunk, ts_ns)
    }
}

/// Mock gate client that simulates an idle timeout (> 5 seconds).
struct TimingOutGateClient;

impl EgressGateClient for TimingOutGateClient {
    fn gate_chunk(&self, _d_jcs: &[u8], _chunk: &[u8]) -> EnclaveResult<RedactProofV1> {
        Err(err!(
            EPERM,
            "ZK_EGRESS_GATE_UNAVAILABLE",
            "Gate request timed out after 5.0s"
        ))
    }
}

#[test]
fn test_4mib_payload_released_incrementally() {
    let sk = SigningKey::generate(&mut rand_core::OsRng);
    let vk = sk.verifying_key();
    let gate = Arc::new(LocalRedactGateClient::new(sk));
    let proxy = ToolEgressProxy::with_client(gate.clone(), vk);

    // 4 MiB payload = 4 * 1024 * 1024 bytes = exactly 64 chunks of 64 KiB
    let total_bytes = 4 * 1024 * 1024;
    let mut payload = Vec::with_capacity(total_bytes);
    for i in 0..total_bytes {
        // Safe scrubbed ASCII bytes ('A'..'Z')
        payload.push(b'A' + (i % 26) as u8);
    }

    let d_jcs = b"{\"action\":\"export_scrubbed_dataset\",\"rows\":4096}";
    let mut sink = Vec::new();

    let written = proxy.stream_egress(d_jcs, &payload, &mut sink).unwrap();

    assert_eq!(written, total_bytes);
    assert_eq!(sink.len(), total_bytes);
    assert_eq!(sink, payload);

    // Exactly 64 chunks gated
    assert_eq!(
        gate.calls.load(Ordering::SeqCst),
        total_bytes.div_ceil(MAX_CHUNK_SIZE - 256)
    );
}

#[test]
fn test_unredacted_ssn_chunk_never_released_sink_sees_zero_bytes_of_it() {
    let sk = SigningKey::generate(&mut rand_core::OsRng);
    let vk = sk.verifying_key();
    let gate = Arc::new(LocalRedactGateClient::new(sk));
    let proxy = ToolEgressProxy::with_client(gate.clone(), vk);

    let d_jcs = b"{\"action\":\"export_report\"}";

    // Case 1: Chunk 1 contains unredacted SSN. Sink must receive exactly 0 bytes total.
    let mut dirty_chunk_1 = vec![b'X'; MAX_CHUNK_SIZE];
    dirty_chunk_1[100..111].copy_from_slice(b"123-45-6789");

    let mut sink_1 = Vec::new();
    let err_1 = proxy
        .stream_egress(d_jcs, &dirty_chunk_1, &mut sink_1)
        .unwrap_err();
    assert!(
        err_1.is("UNREDACTED_C4_IN_EGRESS"),
        "Expected UNREDACTED_C4_IN_EGRESS, got {err_1}"
    );
    assert_eq!(
        sink_1.len(),
        0,
        "Downstream sink must have seen 0 bytes of dirty chunk 1"
    );

    // Case 2: Chunk 1 is clean, but Chunk 2 contains unredacted SSN.
    // Sink must receive exactly Chunk 1 (64 KiB) and 0 bytes of Chunk 2!
    let clean_chunk_1 = vec![b'A'; MAX_CHUNK_SIZE];
    let mut dirty_chunk_2 = vec![b'B'; MAX_CHUNK_SIZE];
    dirty_chunk_2[50..61].copy_from_slice(b"987-65-4321");

    let mut two_chunk_payload = Vec::new();
    two_chunk_payload.extend_from_slice(&clean_chunk_1);
    two_chunk_payload.extend_from_slice(&dirty_chunk_2);

    let mut sink_2 = Vec::new();
    let err_2 = proxy
        .stream_egress(d_jcs, &two_chunk_payload, &mut sink_2)
        .unwrap_err();
    assert!(
        err_2.is("UNREDACTED_C4_IN_EGRESS"),
        "Expected UNREDACTED_C4_IN_EGRESS, got {err_2}"
    );
    assert_eq!(
        sink_2.len(),
        MAX_CHUNK_SIZE - 256,
        "Sink contains only the verified clean release prefix"
    );
    assert_eq!(&sink_2[..], &clean_chunk_1[..MAX_CHUNK_SIZE - 256]);
}

#[test]
fn test_timeout_fails_closed_with_zk_egress_gate_unavailable() {
    let gate = Arc::new(TimingOutGateClient);
    let proxy =
        ToolEgressProxy::with_client(gate, SigningKey::from_bytes(&[2; 32]).verifying_key());

    let d_jcs = b"{\"action\":\"export\"}";
    let payload = vec![b'Z'; MAX_CHUNK_SIZE];
    let mut sink = Vec::new();

    let err = proxy.stream_egress(d_jcs, &payload, &mut sink).unwrap_err();
    assert!(
        err.is("ZK_EGRESS_GATE_UNAVAILABLE"),
        "Expected ZK_EGRESS_GATE_UNAVAILABLE, got {err}"
    );
    assert_eq!(sink.len(), 0, "Sink must receive 0 bytes on gate timeout");
}

#[test]
fn test_verify_latency_p50_p99_under_1_5_ms() {
    let sk = SigningKey::generate(&mut rand_core::OsRng);
    let vk = sk.verifying_key();
    let d_jcs = b"{\"action\":\"verify_benchmark\",\"profile\":\"L3\"}";
    let chunk = vec![b'Q'; MAX_CHUNK_SIZE];
    let proof = evaluate_and_prove_chunk(&sk, d_jcs, &chunk, 1_000_000_000).unwrap();

    let expected_d_jcs_hash = *blake3::hash(d_jcs).as_bytes();
    let expected_chunk_hash = *blake3::hash(&chunk).as_bytes();

    let iterations = 1000;
    let mut latencies_us = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let start = Instant::now();
        proof
            .verify(Some(&vk), &expected_d_jcs_hash, &expected_chunk_hash)
            .unwrap();
        let elapsed_us = start.elapsed().as_micros() as u64;
        latencies_us.push(elapsed_us);
    }

    latencies_us.sort_unstable();
    let p50 = latencies_us[iterations / 2];
    let p99 = latencies_us[(iterations * 99) / 100];

    println!(
        "pi_redact verify latency: p50 = {} us, p99 = {} us (target: < 1500 us)",
        p50, p99
    );

    assert!(
        p99 < 1500,
        "pi_redact verify p99 must be under 1.5 ms (1500 us), got {p99} us"
    );
}

#[test]
fn every_identifier_split_is_rejected_before_its_prefix_is_written() {
    for pattern in [b"123-45-6789".as_slice(), b"123456789"] {
        for boundary in [MAX_CHUNK_SIZE, MAX_CHUNK_SIZE - 256] {
            for split in 1..pattern.len() {
                let sk = SigningKey::from_bytes(&[2; 32]);
                let vk = sk.verifying_key();
                let proxy =
                    ToolEgressProxy::with_client(Arc::new(LocalRedactGateClient::new(sk)), vk);
                let mut payload = vec![b'X'; MAX_CHUNK_SIZE + 512];
                let start = boundary - split;
                payload[start..start + pattern.len()].copy_from_slice(pattern);
                let mut sink = Vec::new();
                assert!(proxy
                    .stream_egress(b"context", &payload, &mut sink)
                    .unwrap_err()
                    .is("UNREDACTED_C4_IN_EGRESS"));
                assert!(
                    sink.len() <= start,
                    "identifier prefix escaped at split {split}"
                );
                assert!(sink.iter().all(|b| *b == b'X'));
            }
        }
    }
}
struct DishonestClient {
    sk: SigningKey,
    wrong_context: bool,
    wrong_length: bool,
}
impl EgressGateClient for DishonestClient {
    fn gate_chunk(&self, context: &[u8], chunk: &[u8]) -> EnclaveResult<RedactProofV1> {
        Ok(RedactProofV1::create(
            &self.sk,
            *blake3::hash(if self.wrong_context {
                b"other"
            } else {
                context
            })
            .as_bytes(),
            *blake3::hash(chunk).as_bytes(),
            chunk.len() as u32 + u32::from(self.wrong_length),
            0,
            0,
        ))
    }
}
#[test]
fn custom_clients_cannot_bypass_pinned_signer_context_or_exact_length() {
    let good = SigningKey::from_bytes(&[2; 32]);
    for (key, context, length, reason) in [
        ([3; 32], false, false, "SIGNER_MISMATCH"),
        ([2; 32], true, false, "D_JCS_HASH_MISMATCH"),
        ([2; 32], false, true, "CHUNK_LENGTH_MISMATCH"),
    ] {
        let proxy = ToolEgressProxy::with_client(
            Arc::new(DishonestClient {
                sk: SigningKey::from_bytes(&key),
                wrong_context: context,
                wrong_length: length,
            }),
            good.verifying_key(),
        );
        for payload in [b"clean".as_slice(), b""] {
            let mut sink = Vec::new();
            assert!(proxy
                .stream_egress(b"context", payload, &mut sink)
                .unwrap_err()
                .is(reason));
            assert!(sink.is_empty());
        }
    }
}
