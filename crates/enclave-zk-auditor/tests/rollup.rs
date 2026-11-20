//! FS-705 / ADR-012 / ADR-016 acceptance tests for UID 705.

#[path = "support/relay_peer.rs"]
mod relay_peer;

use std::collections::BTreeMap;
use std::path::PathBuf;

use ed25519_dalek::{Signer, SigningKey};
use enclave_core::audit::{tombstone_message, AuditJournal};
use enclave_core::poseidon2::hash_bytes;
use enclave_core::profile::Profile;
use enclave_crypto::multisig::{QuorumPolicy, QuorumSignature};
use enclave_crypto::tuf::{target_file, RepoBuilder, TufClient};
use enclave_zk_auditor::cohort::{leaf, CohortTree};
use enclave_zk_auditor::quarantine::{
    grant_digest, FaultKind, FaultReport, FleetGrant, Quarantine, Response,
};
use enclave_zk_auditor::relation::{prove_rollup, EpochPublic, HardwareWitness, SlotWitness};
use enclave_zk_auditor::rollup::{ComplianceRollupProofV1, L3_FRAME_BYTES};
use enclave_zk_auditor::slab::{EmteGate, SecureSlabAllocator};
use enclave_zk_auditor::tombstone::{Tombstone, TombstoneKeys};
use enclave_zk_auditor::witness::WitnessFold;
use enclave_zk_auditor::zk::air::{col, EpochAir};
use enclave_zk_auditor::zk::engine::{
    config, trace, verify_epoch, vk_digest, EpochStatement, SlotKind, Val,
};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;

const EXP: &str = "2030-01-01T00:00:00Z";
const NOW: i64 = 1_793_884_860;

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "enclave-zk-{tag}-{}-{}",
        std::process::id(),
        enclave_core::rng::u64()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

struct Signers {
    a: SigningKey,
    b: SigningKey,
}

impl Signers {
    fn new() -> Self {
        Self {
            a: SigningKey::generate(&mut rand_core::OsRng),
            b: SigningKey::generate(&mut rand_core::OsRng),
        }
    }
    fn keys(&self) -> TombstoneKeys {
        TombstoneKeys {
            k703: self.a.verifying_key(),
            k704: self.b.verifying_key(),
        }
    }
    fn tomb(&self, slot: u64, epoch: &str) -> Tombstone {
        let m = tombstone_message(slot, epoch);
        Tombstone {
            slot,
            boot_epoch_id: epoch.into(),
            sig_703: self.a.sign(&m).to_bytes().to_vec(),
            sig_704: self.b.sign(&m).to_bytes().to_vec(),
        }
    }
}

fn public(profile: u8) -> EpochPublic {
    EpochPublic {
        profile,
        policy_blake3: [7; 32],
        tuf_snapshot_root: [8; 32],
        j_prev: hash_bytes(b"genesis", b""),
    }
}

fn slots(n: u64, start: u64, s: &Signers, epoch: &str) -> Vec<SlotWitness> {
    (0..n)
        .map(|i| {
            if i % 7 == 3 {
                SlotWitness::Tombstone(s.tomb(start + i, epoch))
            } else {
                SlotWitness::Fold {
                    seq: start + i,
                    scrubbed: format!("ticket {i}: card [REDACTED_PAN_C4] ok").into_bytes(),
                    qif_delta_mb: 150,
                }
            }
        })
        .collect()
}

fn lines(n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| format!("{{\"line\":{i}}}").into_bytes())
        .collect()
}

fn cohort(n: usize, member: usize) -> (HardwareWitness, CohortTree) {
    let keys: Vec<(Vec<u8>, Vec<u8>)> = (0..n)
        .map(|i| {
            (
                format!("sep-{i}").into_bytes(),
                format!("yk-{i}").into_bytes(),
            )
        })
        .collect();
    let tree = CohortTree::build(keys.iter().map(|(a, b)| leaf(a, b)).collect()).unwrap();
    let w = HardwareWitness {
        pk_sep: keys[member].0.clone(),
        pk_yk: keys[member].1.clone(),
        path: tree.path(member).unwrap(),
        root: tree.root(),
        cohort_size: tree.size(),
    };
    (w, tree)
}

#[test]
fn l2_rollup_carries_attribution_and_verifies() {
    let s = Signers::new();
    let epoch = enclave_core::seq::new_boot_epoch_id();
    let frame = prove_rollup(
        &public(2),
        &[1; 32],
        "acct:payroll",
        &slots(40, 1000, &s, &epoch),
        &lines(40),
        &s.keys(),
        None,
        Some(vec!["3045aa".into()]),
        false,
    )
    .unwrap();
    let f = ComplianceRollupProofV1::verify(&frame, &[enclave_zk_auditor::zk::engine::hiding_vk_digest()]).unwrap();
    assert_eq!((f.profile, f.s_start, f.s_end), (2, 1000, 1039));
    assert!(f.hardware_batch_anchor_sigs.is_some());
    // L2 without batch signatures is refused at build time.
    let e = prove_rollup(
        &public(2),
        &[1; 32],
        "acct:payroll",
        &slots(8, 0, &s, &epoch),
        &lines(1),
        &s.keys(),
        None,
        None,
        false,
    )
    .unwrap_err();
    assert!(e.is("L2_HARDWARE_SIGS_REQUIRED"), "{e}");
}

#[test]
fn l3_frames_are_constant_size_and_indistinguishable() {
    let s = Signers::new();
    let epoch = enclave_core::seq::new_boot_epoch_id();
    let (w1, _) = cohort(48, 5);
    let (w2, _) = cohort(48, 40);
    let a = prove_rollup(
        &public(3),
        &[1; 32],
        "acct:a",
        &slots(9, 10, &s, &epoch),
        &lines(3),
        &s.keys(),
        Some(&w1),
        None,
        true,
    )
    .unwrap();
    let b = prove_rollup(
        &public(3),
        &[2; 32],
        "acct:b",
        &slots(60, 5000, &s, &epoch),
        &lines(90),
        &s.keys(),
        Some(&w2),
        None,
        false,
    )
    .unwrap();
    assert_eq!(a.len(), L3_FRAME_BYTES);
    assert_eq!(b.len(), L3_FRAME_BYTES);
    let (fa, fb) = (
        ComplianceRollupProofV1::verify(&a, &[enclave_zk_auditor::zk::engine::hiding_vk_digest()]).unwrap(),
        ComplianceRollupProofV1::verify(&b, &[enclave_zk_auditor::zk::engine::hiding_vk_digest()]).unwrap(),
    );
    // Same field set, no hardware identifiers, same fleet root.
    let keys = |v: serde_json::Value| v.as_object().unwrap().keys().cloned().collect::<Vec<_>>();
    assert_eq!(keys(fa.json_view()), keys(fb.json_view()));
    assert!(fa.hardware_batch_anchor_sigs.is_none() && fb.hardware_batch_anchor_sigs.is_none());
    assert_eq!(fa.public_inputs.R_fleet_pk, fb.public_inputs.R_fleet_pk);
    // L3 refuses to place hardware signatures on the wire.
    let c = prove_rollup(
        &public(3),
        &[1; 32],
        "acct:a",
        &slots(9, 10, &s, &epoch),
        &lines(3),
        &s.keys(),
        Some(&w1),
        Some(vec!["3045".into()]),
        true,
    )
    .unwrap();
    assert!(ComplianceRollupProofV1::decode(&c)
        .unwrap()
        .hardware_batch_anchor_sigs
        .is_none());
}

#[test]
fn l3_cohort_membership_and_minimum() {
    let s = Signers::new();
    let epoch = enclave_core::seq::new_boot_epoch_id();
    let sl = slots(8, 0, &s, &epoch);
    assert!(prove_rollup(
        &public(3),
        &[1; 32],
        "e",
        &sl,
        &lines(1),
        &s.keys(),
        None,
        None,
        true
    )
    .unwrap_err()
    .is("L3_REQUIRES_COHORT_MEMBERSHIP"));
    let (mut w, _) = cohort(48, 3);
    w.pk_yk = b"yk-intruder".to_vec();
    assert!(prove_rollup(
        &public(3),
        &[1; 32],
        "e",
        &sl,
        &lines(1),
        &s.keys(),
        Some(&w),
        None,
        true
    )
    .unwrap_err()
    .is("HARDWARE_NOT_IN_COHORT"));
    assert!(
        CohortTree::build((0..31).map(|i| leaf(&[i], &[i])).collect())
            .unwrap_err()
            .is("COHORT_TOO_SMALL")
    );
}

#[test]
fn relation_clauses_fail_closed() {
    let s = Signers::new();
    let epoch = enclave_core::seq::new_boot_epoch_id();
    let p = public(2);
    let sig = Some(vec!["30".to_owned()]);
    // Unredacted C4 in a fold.
    let mut sl = slots(8, 0, &s, &epoch);
    sl[1] = SlotWitness::Fold {
        seq: 1,
        scrubbed: b"card 4111 1111 1111 1111 leaked".to_vec(),
        qif_delta_mb: 10,
    };
    assert!(prove_rollup(
        &p,
        &[1; 32],
        "e",
        &sl,
        &lines(1),
        &s.keys(),
        None,
        sig.clone(),
        false
    )
    .unwrap_err()
    .is("UNREDACTED_C4_IN_FOLD"));
    // Gap: slot neither folded nor tombstoned.
    let mut sl = slots(8, 0, &s, &epoch);
    sl.remove(4);
    assert!(prove_rollup(
        &p,
        &[1; 32],
        "e",
        &sl,
        &lines(1),
        &s.keys(),
        None,
        sig.clone(),
        false
    )
    .unwrap_err()
    .is("SLOT_GAP"));
    // Tombstone signed by only one daemon.
    let mut sl = slots(8, 0, &s, &epoch);
    let mut t = s.tomb(3, &epoch);
    t.sig_704 = s.a.sign(&tombstone_message(3, &epoch)).to_bytes().to_vec();
    sl[3] = SlotWitness::Tombstone(t);
    assert!(prove_rollup(
        &p,
        &[1; 32],
        "e",
        &sl,
        &lines(1),
        &s.keys(),
        None,
        sig.clone(),
        false
    )
    .unwrap_err()
    .is("TOMBSTONE_SIGNATURE"));
    // QIF over the 24 h cap.
    let sl: Vec<_> = (0..13)
        .map(|i| SlotWitness::Fold {
            seq: i,
            scrubbed: b"ok".to_vec(),
            qif_delta_mb: 1000,
        })
        .collect();
    assert!(prove_rollup(
        &p,
        &[1; 32],
        "e",
        &sl,
        &lines(1),
        &s.keys(),
        None,
        sig,
        false
    )
    .unwrap_err()
    .is("QIF_BUDGET_EXCEEDED"));
}

#[test]
fn tampered_frames_and_unpinned_vk_rejected() {
    let s = Signers::new();
    let epoch = enclave_core::seq::new_boot_epoch_id();
    let frame = prove_rollup(
        &public(2),
        &[1; 32],
        "e",
        &slots(16, 0, &s, &epoch),
        &lines(4),
        &s.keys(),
        None,
        Some(vec!["30".into()]),
        false,
    )
    .unwrap();
    assert!(ComplianceRollupProofV1::verify(&frame, &[[9; 32]])
        .unwrap_err()
        .is("VK_NOT_IN_TUF_SNAPSHOT"));
    let mut f = ComplianceRollupProofV1::decode(&frame).unwrap();
    // Claim a longer epoch than was proven.
    f.s_end += 1;
    let st = f.statement().unwrap();
    assert!(enclave_zk_auditor::zk::engine::verify_epoch_private(&st, &f.proof)
        .unwrap_err()
        .is("STARK_VERIFY_FAILED"));
    // Swap J_curr.
    let mut f = ComplianceRollupProofV1::decode(&frame).unwrap();
    f.public_inputs.J_curr = hex::encode([0u8; 32]);
    assert!(enclave_zk_auditor::zk::engine::verify_epoch_private(&f.statement().unwrap(), &f.proof).is_err());
}

fn stmt(n: u64) -> EpochStatement {
    EpochStatement {
        vk_digest: vk_digest(),
        profile: 2,
        policy_blake3: [1; 32],
        tuf_snapshot_root: [2; 32],
        qif_cap_mb: 12_000,
        r_fleet_pk: [0; 32],
        j_prev: [4; 32],
        j_curr: [5; 32],
        nullifier_e: [6; 32],
        qif_root_prev: [7; 32],
        qif_root_curr: [8; 32],
        s_start: 0,
        s_end: n - 1,
        used_in: 0,
        used_out: 1600,
        cohort_size: 0,
    }
}

/// A prover that bypasses the native checks and forges the trace cannot
/// produce an accepted proof: the AIR constraints catch it.
#[test]
fn air_soundness_against_forged_traces() {
    let kinds: Vec<SlotKind> = (0..16).map(|_| SlotKind::Fold { delta_mb: 100 }).collect();
    let st = stmt(16);
    type Forge = Box<dyn Fn(&mut [Val], usize)>;
    let forgeries: Vec<(&str, Forge)> = vec![
        (
            "fold_and_tombstone",
            Box::new(|v, w| v[3 * w + col::IS_TOMB] = Val::ONE),
        ),
        (
            "slot_gap",
            Box::new(|v, w| {
                for r in 5..16 {
                    v[r * w + col::SEQ] += Val::ONE;
                }
            }),
        ),
        (
            "uncharged_delta",
            Box::new(|v, w| v[6 * w + col::DELTA] = Val::from_u32(9000)),
        ),
        (
            "neither",
            Box::new(|v, w| v[2 * w + col::IS_FOLD] = Val::ZERO),
        ),
    ];
    for (name, forge) in forgeries {
        let mut t = trace(&kinds, 12_000, 0).unwrap();
        let w = t.width();
        forge(&mut t.values, w);
        let pis = enclave_zk_auditor::zk::engine::make_public_values(&st);
        let cfg = config(&st);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            p3_uni_stark::prove(&cfg, &EpochAir, t, &pis)
        }));
        match r {
            // Debug constraint checker or prover rejected the forged witness.
            Err(_) | Ok(Err(_)) => {}
            Ok(Ok(proof)) => {
                let mut b = Vec::new();
                ciborium::into_writer(&proof, &mut b).unwrap();
                assert!(verify_epoch(&st, &b).is_err(), "forgery {name} verified");
            }
        }
    }
}

#[test]
fn schema_fixtures_valid_and_invalid() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas/examples");
    for ok in [
        "compliance-rollup-proof-v1.example.l2.json",
        "compliance-rollup-proof-v1.example.l3.json",
    ] {
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join(ok)).unwrap()).unwrap();
        ComplianceRollupProofV1::validate_json_view(&v).unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
    for (bad, reason) in [
        ("fri-42-queries", "ROLLUP_FRI_PARAMS"),
        ("l3-4kib-frame", "L3_FRAME_NOT_320KIB"),
        ("l3-with-hw-sigs", "L3_HARDWARE_SIGS_ON_WIRE"),
    ] {
        let p = root.join(format!(
            "invalid/compliance-rollup-proof-v1.invalid.{bad}.json"
        ));
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
        let e = ComplianceRollupProofV1::validate_json_view(&v).unwrap_err();
        assert!(e.is(reason), "{bad}: {e}");
    }
}

#[test]
fn long_epochs_are_proven_as_a_chained_series() {
    use enclave_zk_auditor::relation::{prove_rollup_series, EpochChunk, MAX_SLOTS_PER_FRAME};
    let s = Signers::new();
    let epoch = enclave_core::seq::new_boot_epoch_id();
    let too_many: Vec<SlotWitness> = (0..MAX_SLOTS_PER_FRAME as u64 + 1)
        .map(|i| SlotWitness::Tombstone(s.tomb(i, &epoch)))
        .collect();
    let e = prove_rollup(
        &public(2),
        &[1; 32],
        "e",
        &too_many,
        &lines(1),
        &s.keys(),
        None,
        Some(vec!["30".into()]),
        false,
    )
    .unwrap_err();
    assert!(e.is("EPOCH_SPLIT_REQUIRED"));

    let all: Vec<SlotWitness> = slots(200, 7_000, &s, &epoch)
        .into_iter()
        .map(|w| match w {
            SlotWitness::Fold { seq, scrubbed, .. } => SlotWitness::Fold {
                seq,
                scrubbed,
                qif_delta_mb: 10,
            },
            t => t,
        })
        .collect();
    let chunks: Vec<EpochChunk> = all
        .chunks(50)
        .map(|c| EpochChunk {
            slots: c.to_vec(),
            journal_lines: lines(c.len()),
        })
        .collect();
    let frames = prove_rollup_series(
        &public(2),
        &[1; 32],
        "e",
        &chunks,
        &s.keys(),
        None,
        Some(vec!["30".into()]),
        false,
    )
    .unwrap();
    assert_eq!(frames.len(), 4);
    let fs: Vec<_> = frames
        .iter()
        .map(|f| ComplianceRollupProofV1::verify(f, &[enclave_zk_auditor::zk::engine::hiding_vk_digest()]).unwrap())
        .collect();
    ComplianceRollupProofV1::verify_series(&frames, &[enclave_zk_auditor::zk::engine::hiding_vk_digest()]).unwrap();
    for w in fs.windows(2) {
        assert_eq!(w[0].s_end + 1, w[1].s_start);
        assert_eq!(w[0].public_inputs.J_curr, w[1].public_inputs.J_prev);
        assert_eq!(w[0].public_inputs.used_out, w[1].public_inputs.used_in);
    }
    assert_eq!((fs[0].s_start, fs[3].s_end), (7_000, 7_199));
    // A dropped chunk is a gap.
    let mut gap = chunks.clone();
    gap.remove(1);
    assert!(prove_rollup_series(
        &public(2),
        &[1; 32],
        "e",
        &gap,
        &s.keys(),
        None,
        Some(vec!["30".into()]),
        false
    )
    .unwrap_err()
    .is("SLOT_GAP"));
    // QIF is enforced across the whole series (3 x 50 x 100 mb > 12,000).
    let heavy: Vec<EpochChunk> = (0..3u64)
        .map(|c| EpochChunk {
            slots: (0..50)
                .map(|i| SlotWitness::Fold {
                    seq: c * 50 + i,
                    scrubbed: b"ok".to_vec(),
                    qif_delta_mb: 100,
                })
                .collect(),
            journal_lines: lines(1),
        })
        .collect();
    assert!(prove_rollup_series(
        &public(2),
        &[1; 32],
        "e",
        &heavy,
        &s.keys(),
        None,
        Some(vec!["30".into()]),
        false
    )
    .unwrap_err()
    .is("QIF_BUDGET_EXCEEDED"));
}

#[test]
fn proof_size_scales_within_budget() {
    let s = Signers::new();
    let epoch = enclave_core::seq::new_boot_epoch_id();
    for n in [8u64, 16, 32, 64] {
        let sl: Vec<_> = (0..n)
            .map(|i| {
                if i % 2 == 0 {
                    SlotWitness::Tombstone(s.tomb(i, &epoch))
                } else {
                    SlotWitness::Fold {
                        seq: i,
                        scrubbed: b"ok".to_vec(),
                        qif_delta_mb: 1,
                    }
                }
            })
            .collect();
        let t = std::time::Instant::now();
        match prove_rollup(
            &public(2),
            &[1; 32],
            "e",
            &sl,
            &lines(1),
            &s.keys(),
            None,
            Some(vec!["30".into()]),
            false,
        ) {
            Ok(frame) => {
                let f = ComplianceRollupProofV1::decode(&frame).unwrap();
                println!(
                    "slots={n} proof={} frame={} prove={:?}",
                    f.proof_bytes_len,
                    frame.len(),
                    t.elapsed()
                );
                assert!(
                    f.proof_bytes_len <= enclave_zk_auditor::zk::engine::MAX_PROOF_BYTES as u64
                );
            }
            Err(e) => panic!("slots={n}: {e}"),
        }
    }
}

#[test]
fn quarantine_strikes_and_quorum_recovery() {
    let d = tmpdir("q");
    let p = d.join("strikes");
    let mut q = Quarantine::open(Profile::L2, &p).unwrap();
    let f = |k, a| FaultReport {
        kind: k,
        fault_addr: a,
        at_ms: 1_000,
    };
    assert_eq!(
        q.report(f(FaultKind::Segv, 0x10)).unwrap(),
        Response::RestartThrottled
    );
    assert_eq!(
        q.report(f(FaultKind::HeapTag, 0xdead_0000)).unwrap(),
        Response::StrikeDelayRespawn
    );
    assert_eq!(
        q.report(f(FaultKind::Redzone, 0xdead_1000)).unwrap(),
        Response::Latched
    );
    // Persisted across restarts; tampering with the counter latches.
    drop(q);
    let q2 = Quarantine::open(Profile::L2, &p).unwrap();
    assert!(q2
        .ensure_clear()
        .unwrap_err()
        .is("HARDWARE_INTEGRITY_QUARANTINE"));
    drop(q2);
    // A forged "clean" body without the sealing key is tampering.
    let forged = std::fs::read_to_string(p.join("quarantine.sealed"))
        .unwrap()
        .replace("true", "false");
    std::fs::write(p.join("quarantine.sealed"), forged).unwrap();
    let q2 = Quarantine::open(Profile::L2, &p).unwrap();
    assert!(q2.is_latched() && q2.integrity_failure().is_some());
    drop(q2);
    // 2-of-3 custodian grant bound to host + cdhash.
    let sks: Vec<SigningKey> = (0..3)
        .map(|_| SigningKey::generate(&mut rand_core::OsRng))
        .collect();
    let pol = QuorumPolicy::new(sks.iter().map(|k| k.verifying_key()).collect(), 2).unwrap();
    let dg = grant_digest("host-17", "cdhash-fixed");
    let sig = |i: usize| QuorumSignature {
        public_key: sks[i].verifying_key().to_bytes().to_vec(),
        signature: sks[i].sign(&dg).to_bytes().to_vec(),
        collected_at_ms: 5_000,
    };
    let mut q3 = Quarantine::open(Profile::L2, &p).unwrap();
    assert!(q3
        .unquarantine_quorum(&pol, "host-17", "cdhash-fixed", &[sig(0)], 6_000)
        .is_err());
    q3.unquarantine_quorum(&pol, "host-17", "cdhash-fixed", &[sig(0), sig(2)], 6_000)
        .unwrap();
    q3.ensure_clear().unwrap();
}

/// A single TUF-signed fleet grant recovers 1,000 latched nodes; a grant for a
/// different binary recovers none.
#[test]
fn fleet_grant_recovers_one_thousand_nodes() {
    let d = tmpdir("fleet");
    let grant = serde_json::to_vec(&FleetGrant {
        cdhash: "cdhash-v3.0.1".into(),
        incident: "INC-2207".into(),
    })
    .unwrap();
    let repo = RepoBuilder::new(3, 2);
    let root = repo.root(EXP).unwrap();
    let mut t = BTreeMap::new();
    t.insert(
        "unquarantine-grant.json".to_owned(),
        target_file(&grant, None),
    );
    let targets = repo.targets(1, EXP, t).unwrap();
    let snap = repo.snapshot(1, EXP, 1, &targets).unwrap();
    let ts = repo.timestamp(1, EXP, 1, &snap).unwrap();
    let mut tuf = TufClient::bootstrap(&root).unwrap();
    tuf.refresh(&ts, &snap, &targets, NOW).unwrap();
    let mut recovered = 0;
    for i in 0..1000 {
        let mut q = Quarantine::open(Profile::L3, &d.join(format!("n{i}"))).unwrap();
        assert_eq!(
            q.report(FaultReport {
                kind: FaultKind::HeapTag,
                fault_addr: 0xbad0_0000,
                at_ms: 1
            })
            .unwrap(),
            Response::Latched
        );
        if i == 0 {
            assert!(q
                .unquarantine_fleet(&tuf, &grant, "cdhash-v3.0.0", NOW)
                .unwrap_err()
                .is("FLEET_GRANT_CDHASH_MISMATCH"));
            let mut forged = grant.clone();
            forged[3] ^= 1;
            assert!(q
                .unquarantine_fleet(&tuf, &forged, "cdhash-v3.0.1", NOW)
                .is_err());
        }
        q.unquarantine_fleet(&tuf, &grant, "cdhash-v3.0.1", NOW)
            .unwrap();
        q.ensure_clear().unwrap();
        recovered += 1;
    }
    assert_eq!(recovered, 1000);
    let _ = std::fs::remove_dir_all(d);
}

/// Touching the byte immediately past a root key traps on the trailing
/// `PROT_NONE` guard page. Runs in a child process.
#[test]
fn root_key_overflow_hits_guard_page() {
    if std::env::var_os("ENCLAVE_GUARD_CHILD").is_some() {
        let mut a = SecureSlabAllocator::new(&EmteGate::default());
        let k = a.alloc_root_key(&[0x5a; 32]).unwrap();
        assert_eq!(k.expose().unwrap(), &[0x5a; 32]);
        let p = k.one_past_end() as *const u8;
        // SAFETY: deliberately faulting read for the test; the process dies.
        let v = unsafe { std::ptr::read_volatile(p) };
        println!("UNREACHABLE {v}");
        std::process::exit(0);
    }
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "root_key_overflow_hits_guard_page",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ENCLAVE_GUARD_CHILD", "1")
        .output()
        .unwrap();
    use std::os::unix::process::ExitStatusExt;
    let sig = out.status.signal();
    assert!(
        matches!(sig, Some(libc::SIGSEGV) | Some(libc::SIGBUS)),
        "child status {:?} stdout {}",
        out.status,
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("UNREACHABLE"));
}

struct TestPeers {
    s: Signers,
    rogue_703: std::sync::atomic::AtomicBool,
    relayed: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    /// UID 703's released slots and its next unissued slot.
    witness: std::sync::Mutex<(Vec<WitnessFold>, u64)>,
    /// UID 703's current epoch and its SEP epoch key (GAP-27).
    epoch: std::sync::Mutex<String>,
    epoch_key: std::sync::Mutex<enclave_crypto::epoch::EpochSigner>,
}

impl TestPeers {
    fn new() -> Self {
        Self {
            s: Signers::new(),
            rogue_703: false.into(),
            relayed: Default::default(),
            witness: Default::default(),
            epoch: Default::default(),
            epoch_key: std::sync::Mutex::new(enclave_crypto::epoch::EpochSigner::random()),
        }
    }
    fn with_epoch(epoch: &str) -> Self {
        let p = Self::new();
        *p.epoch.lock().unwrap() = epoch.to_owned();
        p
    }
}

impl enclave_zk_auditor::service::Peers for TestPeers {
    fn cosign(
        &self,
        who: enclave_core::daemon::DaemonId,
        slot: u64,
        epoch: &str,
    ) -> enclave_core::error::EnclaveResult<(Vec<u8>, Vec<u8>)> {
        use enclave_core::daemon::DaemonId;
        let m = tombstone_message(slot, epoch);
        let k = match who {
            DaemonId::CustodyVault if self.rogue_703.load(std::sync::atomic::Ordering::SeqCst) => {
                SigningKey::generate(&mut rand_core::OsRng)
            }
            DaemonId::CustodyVault => self.s.a.clone(),
            _ => self.s.b.clone(),
        };
        Ok((
            k.sign(&m).to_bytes().to_vec(),
            k.verifying_key().to_bytes().to_vec(),
        ))
    }
    fn prepare_relay(&self, frame: &[u8]) -> enclave_core::error::EnclaveResult<enclave_core::ipc::PreparedCall> {
        let relayed = self.relayed.clone();
        relay_peer::prepare_queued(frame, move |bytes| relayed.lock().unwrap().push(bytes))
    }
    fn fetch_witness(
        &self,
        _e: &str,
        s: u64,
        e: u64,
    ) -> enclave_core::error::EnclaveResult<(Vec<WitnessFold>, u64)> {
        let w = self.witness.lock().unwrap();
        Ok((
            w.0.iter()
                .filter(|f| (s..=e).contains(&f.rpc_seq_u64))
                .cloned()
                .collect(),
            w.1,
        ))
    }
    fn boot_epoch(&self) -> enclave_core::error::EnclaveResult<enclave_core::seq::BootEpoch> {
        Ok(self
            .epoch_key
            .lock()
            .unwrap()
            .sign(&self.epoch.lock().unwrap()))
    }
}

struct P(std::sync::Arc<TestPeers>);
impl enclave_zk_auditor::service::Peers for P {
    fn cosign(
        &self,
        w: enclave_core::daemon::DaemonId,
        s: u64,
        e: &str,
    ) -> enclave_core::error::EnclaveResult<(Vec<u8>, Vec<u8>)> {
        self.0.cosign(w, s, e)
    }
    fn prepare_relay(&self, f: &[u8]) -> enclave_core::error::EnclaveResult<enclave_core::ipc::PreparedCall> {
        self.0.prepare_relay(f)
    }
    fn fetch_witness(
        &self,
        e: &str,
        s: u64,
        t: u64,
    ) -> enclave_core::error::EnclaveResult<(Vec<WitnessFold>, u64)> {
        self.0.fetch_witness(e, s, t)
    }
    fn boot_epoch(&self) -> enclave_core::error::EnclaveResult<enclave_core::seq::BootEpoch> {
        self.0.boot_epoch()
    }
}

/// The daemon journals of one host, written the way UIDs 703 / 704 write them.
struct Journals {
    dir: PathBuf,
    vault: AuditJournal,
    ifc: AuditJournal,
}

impl Journals {
    fn new(dir: &std::path::Path) -> Self {
        use enclave_core::daemon::DaemonId;
        let open = |d: DaemonId| {
            let p = dir
                .join(d.dir_name())
                .join(format!("{}-audit.jsonl", d.plist_suffix()));
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            AuditJournal::open(&p, d, enclave_core::seq::new_boot_epoch_id()).unwrap()
        };
        Self {
            dir: dir.to_owned(),
            vault: open(DaemonId::CustodyVault),
            ifc: open(DaemonId::AgentRuntime),
        }
    }
    /// A slot UID 703 scrubbed and released (journal line + fold witness).
    fn vault_fold(&mut self, p: &TestPeers, epoch: &str, slot: u64, scrubbed: &str) {
        self.vault
            .append_at(
                epoch,
                slot,
                serde_json::json!({"event": "SCRUB_TEXT", "slot": slot}),
            )
            .unwrap();
        p.witness.lock().unwrap().0.push(WitnessFold {
            rpc_seq_u64: slot,
            scrubbed: scrubbed.as_bytes().to_vec(),
            c_raw: "1".repeat(64),
            h_ingress_mac: "2".repeat(64),
        });
    }
    /// A slot UID 704 released, charging `mb` millibits.
    fn ifc_fold(&mut self, epoch: &str, slot: u64, mb: u64) {
        self.ifc
            .append_at(
                epoch,
                slot,
                serde_json::json!({"event": "DECLASSIFY_ENUM", "slot": slot, "qif_mb": mb}),
            )
            .unwrap();
    }
}

#[test]
fn service_derives_witnesses_cosigns_relays_and_chains_journal() {
    use enclave_zk_auditor::service::{
        ProveEpochRequest, ZkConfig, ZkRequest, ZkResponse, ZkService,
    };
    let d = tmpdir("svc-prove");
    let logs = d.join("log");
    let epoch = enclave_core::seq::new_boot_epoch_id();
    let peers = std::sync::Arc::new(TestPeers::with_epoch(&epoch));
    let mut j = Journals::new(&logs);
    // Slots 100..130: i % 4 == 0 aborted (no journal line), i % 4 == 1 a vault
    // scrub, otherwise an orchestrator release charging 40 mb.
    for i in 100..130u64 {
        match i % 4 {
            0 => {}
            1 => j.vault_fold(&peers, &epoch, i, "[REDACTED_SSN_C4]"),
            _ => j.ifc_fold(&epoch, i, 40),
        }
    }
    peers.witness.lock().unwrap().1 = 130;
    let (w, _) = cohort(40, 9);
    let w_clone = w.clone();
    let d_clone = d.clone();
    let peers_clone = peers.clone();
    let mk = move |journal_dir: Option<PathBuf>| {
        // Each instance has its own quarantine state directory.
        ZkService::start(
            ZkConfig {
                profile: Profile::L3,
                quarantine_dir: d_clone.join(format!("q-{}", enclave_core::rng::u64())),
                audit_path: Some(d_clone.join("zk-audit.jsonl")),
                journal_dir,
                socket_dir: None,
                entity: "acct:payroll".into(),
                id_enclave: [3; 32],
                policy_blake3: [7; 32],
                tuf_snapshot_root: [8; 32],
                hardware: Some(w_clone.clone()),
                hardware_batch_anchor_sigs: None,
                receiver_trust: None,
                heartbeat: false,
            },
            Box::new(P(peers_clone.clone())),
        )
        .unwrap()
    };
    let svc = mk(Some(j.dir.clone()));
    let peer = enclave_core::ipc::PeerCredentials {
        uid: 704,
        gid: 704,
        pid: Some(1),
        audit_token: None,
        code_identity: None,
        tls_channel_binding: None,
    };
    let req = |s_start: u64, s_end: u64| ProveEpochRequest {
        boot_epoch_id: epoch.clone(),
        s_start,
        s_end,
    };
    let prove = |a: u64, b: u64| svc.handle(&peer, ZkRequest::ProveEpoch(Box::new(req(a, b))));

    // Slots not yet issued by UID 703 cannot be proven (or tombstoned).
    assert!(prove(120, 130).unwrap_err().is("EPOCH_SLOT_UNISSUED"));
    let ZkResponse::Proven {
        frames,
        relayed,
        j_curr,
    } = prove(100, 109).unwrap()
    else {
        panic!()
    };
    assert!(relayed);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].len(), L3_FRAME_BYTES);
    assert_eq!(peers.relayed.lock().unwrap().len(), 1);
    let ZkResponse::Proven { frames: f2, .. } = prove(110, 119).unwrap() else {
        panic!()
    };
    let second = ComplianceRollupProofV1::decode(&f2[0]).unwrap();
    assert_eq!(
        second.public_inputs.J_prev, j_curr,
        "journal chains across epochs"
    );
    let v = ComplianceRollupProofV1::verify(&f2[0], &[enclave_zk_auditor::zk::engine::hiding_vk_digest()]).unwrap();
    assert_eq!(v.s_end - v.s_start + 1, 10);
    // A range is proven once.
    assert!(prove(105, 125).unwrap_err().is("EPOCH_ALREADY_PROVEN"));

    // The QIF charge is what UID 704 journaled, not what anyone claims.
    j.ifc_fold(&epoch, 130, 12_001);
    peers.witness.lock().unwrap().1 = 131;
    assert!(prove(120, 130).unwrap_err().is("QIF_BUDGET_EXCEEDED"));

    // A witness UID 703 never journaled is not evidence.
    peers.witness.lock().unwrap().0.push(WitnessFold {
        rpc_seq_u64: 131,
        scrubbed: vec![],
        c_raw: "1".repeat(64),
        h_ingress_mac: "2".repeat(64),
    });
    peers.witness.lock().unwrap().1 = 132;
    assert!(prove(120, 131).unwrap_err().is("WITNESS_UNJOURNALED"));

    // GAP-27: only UID 703's current signed epoch is proven, and only under
    // the pinned SEP epoch key.
    let mut other = req(120, 123);
    other.boot_epoch_id = enclave_core::seq::new_boot_epoch_id();
    assert!(svc
        .handle(&peer, ZkRequest::ProveEpoch(Box::new(other)))
        .unwrap_err()
        .is("EPOCH_NOT_CURRENT"));
    let real_key = std::mem::replace(
        &mut *peers.epoch_key.lock().unwrap(),
        enclave_crypto::epoch::EpochSigner::random(),
    );
    assert!(prove(120, 123).unwrap_err().is("EPOCH_SIGNER_CHANGED"));
    *peers.epoch_key.lock().unwrap() = real_key;

    // A co-signer whose key changes mid-life is refused.
    peers
        .rogue_703
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(prove(120, 123).unwrap_err().is("TOMBSTONE_KEY_CHANGED"));
    peers
        .rogue_703
        .store(false, std::sync::atomic::Ordering::SeqCst);

    // Rewriting one journal byte after it was proven breaks every later proof.
    let vp = logs
        .join(enclave_core::daemon::DaemonId::AgentRuntime.dir_name())
        .join("ifc-audit.jsonl");
    let mut b = std::fs::read(&vp).unwrap();
    let k = b.windows(5).position(|w| w == b"\"qif_").unwrap() + 8;
    b[k] = if b[k] == b'4' { b'5' } else { b'4' };
    std::fs::write(&vp, b).unwrap();
    let e = prove(120, 127).unwrap_err();
    assert!(e.to_string().contains("AUDIT_"), "{e}");

    // Without the journals, UID 705 proves nothing.
    let bare = mk(None);
    let e = bare
        .handle(&peer, ZkRequest::ProveEpoch(Box::new(req(124, 127))))
        .unwrap_err();
    assert!(e.is("ZK_NO_JOURNALS"), "{e}");
    enclave_core::audit::verify_journal(&d.join("zk-audit.jsonl"), None).unwrap();
}

#[test]
fn service_refuses_verification_while_quarantined() {
    use enclave_zk_auditor::service::{ZkConfig, ZkRequest, ZkResponse, ZkService};
    let d = tmpdir("svc");
    let peers = TestPeers::new();
    let mut cfg = ZkConfig::new(Profile::L3, d.join("q"));
    cfg.audit_path = Some(d.join("a.jsonl"));
    let (configured_cohort,_) = cohort(32,0);
    cfg.receiver_trust=Some(enclave_zk_auditor::receiver_trust::ReceiverTrust::l3_cohort(
        enclave_zk_auditor::cohort::digest_bytes(&configured_cohort.root),32).unwrap());
    let svc = ZkService::start(cfg, Box::new(peers)).unwrap();
    let peer = enclave_core::ipc::PeerCredentials {
        uid: 704,
        gid: 704,
        pid: Some(1),
        audit_token: None,
        code_identity: None,
        tls_channel_binding: None,
    };
    match svc.handle(&peer, ZkRequest::Status).unwrap() {
        ZkResponse::Status(s) => assert!(s.state.contains("silicon=PacGuarded"), "{}", s.state),
        r => panic!("{r:?}"),
    }
    let s = Signers::new();
    let epoch = enclave_core::seq::new_boot_epoch_id();
    let (w, _) = cohort(32, 0);
    let frame = prove_rollup(
        &public(3),
        &[1; 32],
        "e",
        &slots(8, 0, &s, &epoch),
        &lines(2),
        &s.keys(),
        Some(&w),
        None,
        true,
    )
    .unwrap();
    assert!(matches!(
        svc.handle(
            &peer,
            ZkRequest::VerifyFrame {
                frame: serde_bytes::ByteBuf::from(frame.clone())
            }
        )
        .unwrap(),
        ZkResponse::Verified {
            profile: 3,
            slots: 8
        }
    ));
    // GAP-12: a peer daemon cannot latch the quarantine; only root (the
    // supervisor) or the dev UID reports faults.
    let fault = FaultReport {
        kind: FaultKind::HeapTag,
        fault_addr: 0x4000_0000,
        at_ms: 9,
    };
    if enclave_core::ipc::geteuid() != 704 {
        assert!(svc
            .handle(&peer, ZkRequest::ReportFault(fault))
            .unwrap_err()
            .is("FAULT_REPORTER_REJECTED"));
    }
    if enclave_core::ipc::geteuid() != 701 {
        let m = enclave_core::ipc::PeerCredentials::local(701, 701);
        assert!(svc
            .handle(&m, ZkRequest::ReportFault(fault))
            .unwrap_err()
            .is("FAULT_REPORTER_REJECTED"));
    }
    assert!(
        matches!(svc.handle(&peer, ZkRequest::Status).unwrap(), ZkResponse::Status(s) if s.state.contains("quarantine_latched=false"))
    );
    let sup = enclave_core::ipc::PeerCredentials::local(enclave_core::ipc::geteuid(), 0);
    let r = svc.handle(&sup, ZkRequest::ReportFault(fault)).unwrap();
    assert!(
        matches!(r, ZkResponse::Fault(Response::Latched)),
        "L3 latches on the first strike"
    );
    let e = svc
        .handle(
            &peer,
            ZkRequest::VerifyFrame {
                frame: serde_bytes::ByteBuf::from(frame),
            },
        )
        .unwrap_err();
    assert!(e.is("HARDWARE_INTEGRITY_QUARANTINE"));
    let journal = std::fs::read_to_string(d.join("a.jsonl")).unwrap();
    assert!(journal.contains("INTEGRITY_FAULT"));
    enclave_core::audit::verify_journal(&d.join("a.jsonl"), None).unwrap();
}
