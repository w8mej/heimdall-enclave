use enclave_zk_auditor::zk::engine::{
    prove_epoch, verify_epoch, vk_digest, EpochStatement, SlotKind,
};

fn stmt(n: u64) -> EpochStatement {
    EpochStatement {
        vk_digest: vk_digest(),
        profile: 3,
        policy_blake3: [1; 32],
        tuf_snapshot_root: [2; 32],
        qif_cap_mb: 12_000,
        r_fleet_pk: [3; 32],
        j_prev: [4; 32],
        j_curr: [5; 32],
        nullifier_e: [6; 32],
        qif_root_prev: [7; 32],
        qif_root_curr: [8; 32],
        s_start: 88_514,
        s_end: 88_514 + n - 1,
        used_in: 0,
        used_out: 9500,
        cohort_size: 48,
    }
}

#[test]
fn prove_verify_and_size() {
    let slots: Vec<SlotKind> = (0..48)
        .map(|i| {
            if i % 5 == 0 {
                SlotKind::Tombstone
            } else {
                SlotKind::Fold { delta_mb: 250 }
            }
        })
        .collect();
    let s = stmt(48);
    let t = std::time::Instant::now();
    let p = prove_epoch(&s, &slots).unwrap();
    println!("proof bytes = {} prove = {:?}", p.len(), t.elapsed());
    verify_epoch(&s, &p).unwrap();
    let mut bad = s.clone();
    bad.policy_blake3[0] ^= 1;
    assert!(verify_epoch(&bad, &p).is_err());
}
