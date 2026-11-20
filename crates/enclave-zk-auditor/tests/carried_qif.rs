//! GAP-24 (interim): Carried QIF state and journal continuity across frames.
//!
//! Required test coverage:
//! - a 3-frame series each spending 6,000 mb => ledger verification fails
//! - a valid chain passes
//! - a gap or reorder in J => fails
//! - benchmark at 64/512/4096 slots (release, long)

use ed25519_dalek::SigningKey;
use enclave_core::poseidon2::hash_bytes;
use enclave_zk_auditor::relation::{prove_rollup_series, EpochChunk, EpochPublic, SlotWitness};
use enclave_zk_auditor::rollup::ComplianceRollupProofV1;
use enclave_zk_auditor::tombstone::TombstoneKeys;
use enclave_zk_auditor::zk::engine::hiding_vk_digest as vk_digest;

struct Signers {
    k703: SigningKey,
    k704: SigningKey,
}

impl Signers {
    fn new() -> Self {
        let mut csprng = rand_core::OsRng;
        Self {
            k703: SigningKey::generate(&mut csprng),
            k704: SigningKey::generate(&mut csprng),
        }
    }
    fn keys(&self) -> TombstoneKeys {
        TombstoneKeys {
            k703: self.k703.verifying_key(),
            k704: self.k704.verifying_key(),
        }
    }
}

fn dummy_chunk(s_start: u64, count: usize, delta_per_slot: u32) -> EpochChunk {
    let slots = (0..count)
        .map(|i| SlotWitness::Fold {
            seq: s_start + i as u64,
            scrubbed: b"[REDACTED]".to_vec(),
            qif_delta_mb: delta_per_slot,
        })
        .collect();
    let lines = (0..count)
        .map(|i| {
            serde_json::to_vec(&serde_json::json!({
                "log_seq_u64": i + 1,
                "msg": format!("audit line {}", s_start + i as u64)
            }))
            .unwrap()
        })
        .collect();
    EpochChunk {
        slots,
        journal_lines: lines,
    }
}

fn public() -> EpochPublic {
    EpochPublic {
        profile: 2,
        policy_blake3: [1; 32],
        tuf_snapshot_root: [2; 32],
        j_prev: hash_bytes(b"MCPMac-Genesis-v1", b""),
    }
}

// ---------------------------------------------------------------------------
// TEST 1: Valid multi-frame chain passes
// ---------------------------------------------------------------------------
#[test]
fn test_valid_chain_passes() {
    let s = Signers::new();
    let c1 = dummy_chunk(1, 32, 60); // 32 * 60 = 1920 mb
    let c2 = dummy_chunk(33, 32, 70); // 32 * 70 = 2240 mb
    let c3 = dummy_chunk(65, 32, 80); // 32 * 80 = 2560 mb
                                      // Total = 1920 + 2240 + 2560 = 6720 mb <= 12,000 mb

    let frames = prove_rollup_series(
        &public(),
        &[7; 32],
        "acct:corp",
        &[c1, c2, c3],
        &s.keys(),
        None,
        Some(vec!["3045".into()]),
        false,
    )
    .unwrap();

    assert_eq!(frames.len(), 3);
    let decoded = ComplianceRollupProofV1::verify_series(&frames, &[vk_digest()]).unwrap();
    assert_eq!(decoded.len(), 3);

    // Verify carried state transitions
    assert_eq!(decoded[0].public_inputs.used_in, 0);
    assert_eq!(decoded[0].public_inputs.used_out, 1920);

    assert_eq!(decoded[1].public_inputs.used_in, 1920);
    assert_eq!(decoded[1].public_inputs.used_out, 1920 + 2240);

    assert_eq!(decoded[2].public_inputs.used_in, 1920 + 2240);
    assert_eq!(decoded[2].public_inputs.used_out, 6720);

    // Verify journal fold continuity
    assert_eq!(
        decoded[0].public_inputs.J_curr,
        decoded[1].public_inputs.J_prev
    );
    assert_eq!(
        decoded[1].public_inputs.J_curr,
        decoded[2].public_inputs.J_prev
    );
}

// ---------------------------------------------------------------------------
// TEST 2: A 3-frame series each spending 6,000 mb fails ledger verification
// ---------------------------------------------------------------------------
#[test]
fn test_three_frame_series_each_spending_6000_fails_ledger_verification() {
    let s = Signers::new();

    // 1. In-series generation fails closed natively: 3 * 6,000 = 18,000 > 12,000
    let c1 = dummy_chunk(1, 30, 200); // 30 * 200 = 6000 mb
    let c2 = dummy_chunk(31, 30, 200); // 6000 mb
    let c3 = dummy_chunk(61, 30, 200); // 6000 mb
    let err = prove_rollup_series(
        &public(),
        &[7; 32],
        "acct:corp",
        &[c1.clone(), c2.clone(), c3.clone()],
        &s.keys(),
        None,
        Some(vec!["3045".into()]),
        false,
    )
    .unwrap_err();
    assert!(
        err.is("QIF_BUDGET_EXCEEDED") || err.is("QIF_CAP_EXCEEDED"),
        "expected QIF budget exceeded, got {err}"
    );

    // 2. An attacker tries to bypass series cap by forging/presenting 3 frames
    // generated independently as initial frames (each spending 6,000 with used_in=0):
    let f1 = prove_rollup_series(
        &public(),
        &[7; 32],
        "acct:corp",
        &[c1],
        &s.keys(),
        None,
        Some(vec!["3045".into()]),
        false,
    )
    .unwrap();
    let f2 = prove_rollup_series(
        &public(),
        &[7; 32],
        "acct:corp",
        &[c2],
        &s.keys(),
        None,
        Some(vec!["3045".into()]),
        false,
    )
    .unwrap();
    let f3 = prove_rollup_series(
        &public(),
        &[7; 32],
        "acct:corp",
        &[c3],
        &s.keys(),
        None,
        Some(vec!["3045".into()]),
        false,
    )
    .unwrap();

    let combined = vec![f1[0].clone(), f2[0].clone(), f3[0].clone()];

    // Ledger verifier MUST reject the chain because frame 1 has used_in=0 != frame 0 used_out=6000
    let err = ComplianceRollupProofV1::verify_series(&combined, &[vk_digest()]).unwrap_err();
    assert!(
        err.is("QIF_CHAIN_BREAK") || err.is("JOURNAL_CHAIN_BREAK"),
        "expected QIF_CHAIN_BREAK, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// TEST 3: A gap or reorder in J fails ledger verification
// ---------------------------------------------------------------------------
#[test]
fn test_gap_or_reorder_in_j_fails() {
    let s = Signers::new();
    let c1 = dummy_chunk(1, 10, 10);
    let c2 = dummy_chunk(11, 10, 10);

    let frames = prove_rollup_series(
        &public(),
        &[7; 32],
        "acct:corp",
        &[c1, c2],
        &s.keys(),
        None,
        Some(vec!["3045".into()]),
        false,
    )
    .unwrap();

    // Reorder: frame 1 before frame 0
    let reordered = vec![frames[1].clone(), frames[0].clone()];
    let err = ComplianceRollupProofV1::verify_series(&reordered, &[vk_digest()]).unwrap_err();
    assert!(
        err.is("QIF_INITIAL_NONZERO") || err.is("SLOT_GAP") || err.is("JOURNAL_CHAIN_BREAK"),
        "expected sequence or chain break on reorder, got: {err}"
    );

    // Tamper with J_prev in frame 1
    let mut frame1_decoded = ComplianceRollupProofV1::decode(&frames[1]).unwrap();
    frame1_decoded.public_inputs.J_prev =
        "0000000000000000000000000000000000000000000000000000000000000000".into();
    let mut tampered_bytes = Vec::new();
    ciborium::into_writer(&frame1_decoded, &mut tampered_bytes).unwrap();
    let tampered_series = vec![frames[0].clone(), tampered_bytes];

    let err = ComplianceRollupProofV1::verify_series(&tampered_series, &[vk_digest()]).unwrap_err();
    assert!(
        err.is("JOURNAL_CHAIN_BREAK")
            || err.is("STARK_VERIFY_FAILED")
            || err.is("SERIES_FRAME_INVALID"),
        "expected journal chain break or verify failure, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// BENCHMARK 2B-1: Size benchmark at 64 / 512 / 4,096 slots
// ---------------------------------------------------------------------------
#[test]
#[ignore]
fn bench_proof_size_at_64_512_4096() {
    let s = Signers::new();

    for total_slots in [64, 512, 4096] {
        let chunk_size = 64;
        let num_chunks = total_slots / chunk_size;
        let chunks: Vec<EpochChunk> = (0..num_chunks)
            .map(|i| dummy_chunk(1 + (i * chunk_size) as u64, chunk_size, 1))
            .collect();

        let t0 = std::time::Instant::now();
        let frames = prove_rollup_series(
            &public(),
            &[7; 32],
            "acct:bench",
            &chunks,
            &s.keys(),
            None,
            Some(vec!["3045".into()]),
            false,
        )
        .unwrap();
        let prove_dur = t0.elapsed();

        let t1 = std::time::Instant::now();
        let verified = ComplianceRollupProofV1::verify_series(&frames, &[vk_digest()]).unwrap();
        let verify_dur = t1.elapsed();

        let total_bytes: usize = frames.iter().map(|f| f.len()).sum();
        let max_frame_bytes = frames.iter().map(|f| f.len()).max().unwrap();

        println!(
            "BENCHMARK 2B-1: slots={} chunks={} frame_max_bytes={} total_bytes={} prove={:?} verify={:?}",
            total_slots,
            num_chunks,
            max_frame_bytes,
            total_bytes,
            prove_dur,
            verify_dur
        );

        assert_eq!(verified.len(), num_chunks);
        // Each frame must remain strictly within normative proof size ceiling
        assert!(
            max_frame_bytes <= 128 * 1024,
            "max frame bytes {max_frame_bytes} exceeded ceiling"
        );
    }
}
