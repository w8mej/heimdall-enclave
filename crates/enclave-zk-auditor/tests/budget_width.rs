use ed25519_dalek::SigningKey;
use enclave_core::poseidon2::hash_bytes;
use enclave_zk_auditor::relation::{prove_rollup_at, EpochPublic, SlotWitness};
use enclave_zk_auditor::rollup::{ComplianceRollupProofV1, QIF_CAP_MB};
use enclave_zk_auditor::tombstone::TombstoneKeys;
use enclave_zk_auditor::zk::engine::{trace, hiding_vk_digest as vk_digest, SlotKind};

fn prove(deltas: &[u32], used_in: u32) -> enclave_core::error::EnclaveResult<(Vec<u8>, u32)> {
    let signer = SigningKey::from_bytes(&[17; 32]);
    let keys = TombstoneKeys {
        k703: signer.verifying_key(),
        k704: signer.verifying_key(),
    };
    let slots: Vec<_> = deltas
        .iter()
        .enumerate()
        .map(|(seq, delta)| SlotWitness::Fold {
            seq: seq as u64,
            scrubbed: b"safe payload".to_vec(),
            qif_delta_mb: *delta,
        })
        .collect();
    prove_rollup_at(
        &EpochPublic {
            profile: 2,
            policy_blake3: [1; 32],
            tuf_snapshot_root: [2; 32],
            j_prev: hash_bytes(b"budget-width-test", b"genesis"),
        },
        &[3; 32],
        "budget-width-test",
        &slots,
        &[],
        &keys,
        None,
        // This test exercises accounting, not the missing anchor-authentication
        // control tracked separately as F81.
        Some(vec!["fixture:accounting-only".into()]),
        false,
        used_in,
    )
}

#[test]
fn wrapped_sum_is_rejected_by_native_budget_check_before_proving() {
    for (deltas, entering) in [
        (vec![u32::MAX, 1], 0),
        (vec![u32::MAX, 2], 0),
        (vec![u32::MAX, 1], 6_000),
    ] {
        let actual = u64::from(entering) + deltas.iter().map(|d| u64::from(*d)).sum::<u64>();
        let err = prove(&deltas, entering).unwrap_err();
        assert!(err.is("QIF_BUDGET_EXCEEDED"), "{actual}: {err}");
        assert!(err.to_string().contains(&actual.to_string()), "{err}");
    }
}

#[test]
fn one_millibit_over_budget_is_rejected() {
    for (deltas, entering) in [(vec![QIF_CAP_MB + 1], 0), (vec![1], QIF_CAP_MB)] {
        assert!(prove(&deltas, entering)
            .unwrap_err()
            .is("QIF_BUDGET_EXCEEDED"));
    }
}

#[test]
fn exact_budget_and_zero_charge_still_prove_and_verify() {
    for (deltas, entering) in [(vec![6_000], 6_000), (vec![0], QIF_CAP_MB)] {
        let (frame, used) = prove(&deltas, entering).unwrap();
        assert_eq!(used, QIF_CAP_MB);
        let checked = ComplianceRollupProofV1::verify(&frame, &[vk_digest()]).unwrap();
        assert_eq!(checked.public_inputs.used_in, entering);
        assert_eq!(checked.public_inputs.used_out, QIF_CAP_MB);
    }
}

#[test]
fn trace_generator_enforces_the_fourteen_bit_delta_boundary() {
    let err = trace(&[SlotKind::Fold { delta_mb: 1 << 14 }], (1 << 14) - 1, 0).unwrap_err();
    assert!(err.is("QIF_DELTA_RANGE"));
    assert!(trace(
        &[SlotKind::Fold {
            delta_mb: (1 << 14) - 1
        }],
        (1 << 14) - 1,
        0
    )
    .is_ok());
}

#[test]
fn reproduces_unchanged_qif_placeholders_despite_real_charge() {
    let (bytes, _) = prove(&[6_000], 0).unwrap();
    let frame = ComplianceRollupProofV1::decode(&bytes).unwrap();
    let statement = frame.statement().unwrap();
    assert_eq!(statement.used_in, 0);
    assert_eq!(statement.used_out, 6_000);
    assert_eq!(statement.qif_root_prev, statement.qif_root_curr);
    assert_eq!(statement.r_fleet_pk, [0; 32]);
    // This is explicit vulnerability evidence. No tree/authority is supplied.
}
