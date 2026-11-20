//! Check the actual exported EpochAir polynomials, not only the honest prover.
use enclave_zk_auditor::zk::air::{col, pv, EpochAir, BITS, WIDTH};
use enclave_zk_auditor::zk::engine::{
    prove_epoch, prove_epoch_hiding, trace, verify_epoch, verify_epoch_hiding, vk_digest,
    EpochConfig, EpochStatement, HidingEpochConfig, SlotKind, Val,
};
use p3_air::symbolic::{
    get_symbolic_constraints, AirLayout, BaseEntry, BaseLeaf, SymbolicExpression,
};
use p3_field::PrimeCharacteristicRing;

fn eval(e: &SymbolicExpression<Val>, row: &[Val], public: &[Val]) -> Val {
    // Per-row checks deliberately disable boundary selectors.
    eval_at(e, row, row, public, [Val::ZERO; 3])
}

fn eval_at(
    e: &SymbolicExpression<Val>,
    row: &[Val],
    next: &[Val],
    public: &[Val],
    selectors: [Val; 3],
) -> Val {
    let recurse = |child| eval_at(child, row, next, public, selectors);
    match e {
        SymbolicExpression::Leaf(l) => match l {
            BaseLeaf::Constant(c) => *c,
            BaseLeaf::Variable(v) => match v.entry {
                BaseEntry::Main { offset: 0 } => row[v.index],
                BaseEntry::Main { offset: 1 } => next[v.index],
                BaseEntry::Public => public[v.index],
                other => panic!("unsupported variable {other:?}"),
            },
            BaseLeaf::IsFirstRow => selectors[0],
            BaseLeaf::IsLastRow => selectors[1],
            BaseLeaf::IsTransition => selectors[2],
        },
        SymbolicExpression::Add { x, y, .. } => recurse(x) + recurse(y),
        SymbolicExpression::Sub { x, y, .. } => recurse(x) - recurse(y),
        SymbolicExpression::Mul { x, y, .. } => recurse(x) * recurse(y),
        SymbolicExpression::Neg { x, .. } => -recurse(x),
    }
}

fn empty_accounting_statement(start: u64, end: u64) -> EpochStatement {
    EpochStatement {
        vk_digest: vk_digest(),
        profile: 2,
        policy_blake3: [0; 32],
        tuf_snapshot_root: [0; 32],
        qif_cap_mb: 12000,
        r_fleet_pk: [0; 32],
        j_prev: [0; 32],
        j_curr: [0; 32],
        nullifier_e: [0; 32],
        qif_root_prev: [0; 32],
        qif_root_curr: [0; 32],
        s_start: start,
        s_end: end,
        used_in: 0,
        used_out: 0,
        cohort_size: 32,
    }
}

#[test]
fn actual_span_polynomial_accepts_crossing_u32_boundary() {
    let start = u32::MAX as u64;
    let end = start + 1;
    let mut public = vec![Val::ZERO; enclave_zk_auditor::zk::air::NUM_PUBLIC];
    public[pv::SPAN] = Val::ONE;
    public[pv::S_START_LOW] = Val::from_u32(start as u32);
    public[pv::S_START_HIGH] = Val::from_u32((start >> 32) as u32);
    public[pv::S_END_LOW] = Val::from_u32(end as u32);
    public[pv::S_END_HIGH] = Val::from_u32((end >> 32) as u32);
    let constraints =
        get_symbolic_constraints::<Val, _>(&EpochAir, AirLayout::from_air::<Val>(&EpochAir));
    assert_eq!(
        eval(&constraints[52], &vec![Val::ZERO; WIDTH], &public),
        Val::ZERO
    );
    // The same absolute endpoints cannot claim a different slot span.
    public[pv::SPAN] = Val::from_u32(2);
    assert_ne!(
        eval(&constraints[52], &vec![Val::ZERO; WIDTH], &public),
        Val::ZERO
    );
}

#[test]
fn both_provers_reject_full_u64_span_without_panicking() {
    let statement = empty_accounting_statement(0, u64::MAX);
    assert!(prove_epoch(&statement, &[]).unwrap_err().is("EPOCH_SPAN"));
    assert!(prove_epoch_hiding(&statement, &[], 0)
        .unwrap_err()
        .is("EPOCH_SPAN"));
}

#[test]
fn actual_constraints_enforce_gap_free_nonduplicated_slot_coverage() {
    let matrix = trace(
        &[
            SlotKind::Fold { delta_mb: 500 },
            SlotKind::Tombstone,
            SlotKind::Fold { delta_mb: 1000 },
        ],
        12000,
        2000,
    )
    .unwrap();
    let rows: Vec<Vec<Val>> = matrix
        .values
        .chunks_exact(WIDTH)
        .map(<[Val]>::to_vec)
        .collect();
    let mut public = vec![Val::ZERO; enclave_zk_auditor::zk::air::NUM_PUBLIC];
    public[pv::SPAN] = Val::from_u32(2);
    public[pv::CAP] = Val::from_u32(12000);
    public[pv::USED_IN] = Val::from_u32(2000);
    public[pv::USED_OUT] = Val::from_u32(3500);
    public[pv::S_START_LOW] = Val::from_u32(u32::MAX);
    public[pv::S_END_LOW] = Val::ONE;
    public[pv::S_END_HIGH] = Val::ONE;
    let constraints =
        get_symbolic_constraints::<Val, _>(&EpochAir, AirLayout::from_air::<Val>(&EpochAir));
    let satisfies = |witness: &[Vec<Val>], pis: &[Val]| {
        witness.iter().enumerate().all(|(i, row)| {
            let selectors = [
                Val::from_bool(i == 0),
                Val::from_bool(i + 1 == witness.len()),
                Val::from_bool(i + 1 < witness.len()),
            ];
            let next = &witness[(i + 1) % witness.len()];
            constraints
                .iter()
                .all(|c| eval_at(c, row, next, pis, selectors) == Val::ZERO)
        })
    };
    assert!(
        satisfies(&rows, &public),
        "honest nonzero-charge prefix with padding"
    );
    let mut duplicate = rows.clone();
    duplicate[1][col::SEQ] = Val::ZERO;
    assert!(!satisfies(&duplicate, &public), "duplicate slot offset");
    let mut gap = rows.clone();
    gap[1][col::ACTIVE] = Val::ZERO;
    gap[1][col::IS_TOMB] = Val::ZERO;
    assert!(
        !satisfies(&gap, &public),
        "inactive gap followed by an active row"
    );
    let mut missing_final = rows.clone();
    missing_final[2][col::ACTIVE] = Val::ZERO;
    missing_final[2][col::IS_FOLD] = Val::ZERO;
    assert!(
        !satisfies(&missing_final, &public),
        "claimed span exceeds the active prefix"
    );
    let mut forged_span = public.clone();
    forged_span[pv::SPAN] = Val::from_u32(3);
    forged_span[pv::S_END_LOW] = Val::from_u32(2);
    assert!(
        !satisfies(&rows, &forged_span),
        "endpoints alone cannot extend the trace"
    );
}

#[test]
fn verifier_manifest_names_the_current_relation() {
    let manifest = enclave_zk_auditor::zk::manifest::VkManifestV1::default();
    assert_eq!(manifest.air_domain, enclave_zk_auditor::zk::air::AIR_DOMAIN);
    assert_eq!(manifest.vk_digest_bytes().unwrap(), vk_digest());
    let restored = enclave_zk_auditor::zk::manifest::VkManifestV1::from_json_bytes(
        &manifest.to_json_bytes().unwrap(),
    )
    .unwrap();
    assert_eq!(restored, manifest);
}

#[test]
fn both_proof_configurations_accept_absolute_sequence_limb_boundaries() {
    let slots = [SlotKind::Fold { delta_mb: 500 }, SlotKind::Tombstone];
    for start in [u32::MAX as u64, u64::MAX - 1] {
        let mut statement = empty_accounting_statement(start, start + 1);
        statement.used_in = 1000;
        statement.used_out = 1500;
        let proof = prove_epoch(&statement, &slots).unwrap();
        verify_epoch(&statement, &proof).unwrap();
        let hiding = prove_epoch_hiding(&statement, &slots, 42).unwrap();
        verify_epoch_hiding(&statement, &hiding, 42).unwrap();
        for degree_bits in [25, usize::MAX] {
            let mut malformed: p3_uni_stark::Proof<EpochConfig> =
                ciborium::from_reader(proof.as_slice()).unwrap();
            malformed.degree_bits = degree_bits;
            let mut encoded = Vec::new();
            ciborium::into_writer(&malformed, &mut encoded).unwrap();
            assert!(verify_epoch(&statement, &encoded)
                .unwrap_err()
                .is("STARK_VERIFY_FAILED"));
            let mut malformed: p3_uni_stark::Proof<HidingEpochConfig> =
                ciborium::from_reader(hiding.as_slice()).unwrap();
            malformed.degree_bits = degree_bits;
            let mut encoded = Vec::new();
            ciborium::into_writer(&malformed, &mut encoded).unwrap();
            assert!(verify_epoch_hiding(&statement, &encoded, 42)
                .unwrap_err()
                .is("STARK_VERIFY_FAILED"));
        }
        // Changing the absolute endpoints must invalidate the existing proof.
        statement.s_start -= 1;
        assert!(verify_epoch(&statement, &proof).is_err());
        assert!(verify_epoch_hiding(&statement, &hiding, 42).is_err());
    }
}

#[test]
fn field_wrapped_used_is_rejected_by_actual_air() {
    let mut row = vec![Val::ZERO; WIDTH];
    row[col::USED] = -Val::ONE;
    let slack = 12_001u32;
    for i in 0..BITS {
        row[col::SLACK + i] = Val::from_u32((slack >> i) & 1);
    }
    let mut public = vec![Val::ZERO; enclave_zk_auditor::zk::air::NUM_PUBLIC];
    public[pv::CAP] = Val::from_u32(12_000);
    // The old constraint accepts this p-1 witness.
    assert_eq!(public[pv::CAP] - row[col::USED], Val::from_u32(slack));
    let constraints =
        get_symbolic_constraints::<Val, _>(&EpochAir, AirLayout::from_air::<Val>(&EpochAir));
    assert!(constraints
        .iter()
        .any(|c| eval(c, &row, &public) != Val::ZERO));
    // Putting -1 into a "bit" cannot bypass the new decomposition either.
    row[col::UBITS] = -Val::ONE;
    assert!(constraints
        .iter()
        .any(|c| eval(c, &row, &public) != Val::ZERO));
}

#[test]
fn honest_total_bits_reconstruct_the_actual_used_column() {
    for entering in [0, 1, 6000, 11999, 12000] {
        let matrix = trace(
            &[SlotKind::Fold {
                delta_mb: 12000 - entering,
            }],
            12000,
            entering,
        )
        .unwrap();
        for row in matrix.values.chunks_exact(WIDTH) {
            let reconstructed = (0..BITS).fold(Val::ZERO, |a, i| {
                a + row[col::UBITS + i] * Val::from_u32(1 << i)
            });
            assert_eq!(reconstructed, row[col::USED]);
        }
    }
}

#[test]
fn both_verifiers_reject_noncanonical_public_accounting_before_decoding() {
    let mut statement = EpochStatement {
        vk_digest: vk_digest(),
        profile: 2,
        policy_blake3: [0; 32],
        tuf_snapshot_root: [0; 32],
        qif_cap_mb: 12000,
        r_fleet_pk: [0; 32],
        j_prev: [0; 32],
        j_curr: [0; 32],
        nullifier_e: [0; 32],
        qif_root_prev: [0; 32],
        qif_root_curr: [0; 32],
        s_start: 0,
        s_end: 0,
        used_in: 0,
        used_out: 0,
        cohort_size: 32,
    };
    for (cap, input, output) in [(1 << 14, 0, 0), (12000, 12001, 0), (12000, 0, 12001)] {
        statement.qif_cap_mb = cap;
        statement.used_in = input;
        statement.used_out = output;
        assert!(verify_epoch(&statement, &[])
            .unwrap_err()
            .is("QIF_PUBLIC_RANGE"));
        assert!(verify_epoch_hiding(&statement, &[], 0)
            .unwrap_err()
            .is("QIF_PUBLIC_RANGE"));
    }
}
