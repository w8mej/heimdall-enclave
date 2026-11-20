//! Benchmark single STARK proof size and prove/verify time at 64, 512, and 4,096 slots.

use enclave_zk_auditor::zk::engine::{
    prove_epoch, verify_epoch, vk_digest, EpochStatement, SlotKind,
};

#[test]
fn bench_stark_sizes_64_512_4096() {
    let vk = vk_digest();

    for &num_slots in &[64, 512, 4096] {
        let kinds: Vec<SlotKind> = (0..num_slots)
            .map(|i| {
                if i % 8 == 3 {
                    SlotKind::Tombstone
                } else {
                    SlotKind::Fold { delta_mb: 2 }
                }
            })
            .collect();

        let expected_used: u32 = kinds
            .iter()
            .map(|k| match k {
                SlotKind::Fold { delta_mb } => *delta_mb,
                _ => 0,
            })
            .sum();

        let stmt = EpochStatement {
            vk_digest: vk,
            profile: 2,
            policy_blake3: [1; 32],
            tuf_snapshot_root: [2; 32],
            qif_cap_mb: 12_000,
            r_fleet_pk: [0; 32],
            j_prev: [0; 32],
            j_curr: [0; 32],
            nullifier_e: [3; 32],
            qif_root_prev: [4; 32],
            qif_root_curr: [4; 32],
            s_start: 1,
            s_end: num_slots as u64,
            used_in: 0,
            used_out: expected_used,
            cohort_size: 0,
        };

        let t0 = std::time::Instant::now();
        let proof = prove_epoch(&stmt, &kinds).expect("prove_epoch must succeed");
        let prove_dur = t0.elapsed();

        let t1 = std::time::Instant::now();
        verify_epoch(&stmt, &proof).expect("verify_epoch must succeed");
        let verify_dur = t1.elapsed();

        println!(
            "SLOTS = {:4} | PROOF SIZE = {:6} bytes | PROVE TIME = {:8.2?} | VERIFY TIME = {:8.2?}",
            num_slots,
            proof.len(),
            prove_dur,
            verify_dur
        );
    }
}
