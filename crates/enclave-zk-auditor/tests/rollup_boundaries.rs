//! Hostile wire/sequence controls for accounting frames. These do not close
//! the missing authenticated relation or establish statistical witness privacy.
use enclave_core::poseidon2::hash_bytes;
use enclave_zk_auditor::{
    cohort::digest_bytes,
    relation::{prove_rollup, prove_rollup_series, EpochChunk, EpochPublic, SlotWitness},
    rollup::{ComplianceRollupProofV1 as Frame, RollupTrust, L3_FRAME_BYTES},
    tombstone::TombstoneKeys,
    zk::{
        engine::{hiding_vk_digest, prove_epoch, prove_epoch_hiding, prove_epoch_private,
            verify_epoch, verify_epoch_hiding, verify_epoch_private, vk_digest, EpochStatement, SlotKind},
        manifest::VkManifestV1,
    },
};

fn statement(profile: u8, start: u64, end: u64) -> EpochStatement {
    let nullifier_e = [4; 32];
    let qif = digest_bytes(&hash_bytes(b"depot-QifTree-v1", &nullifier_e));
    EpochStatement {
        vk_digest: vk_digest(),
        profile,
        policy_blake3: [1; 32],
        tuf_snapshot_root: [2; 32],
        qif_cap_mb: 12_000,
        r_fleet_pk: [3; 32],
        j_prev: [4; 32],
        j_curr: [5; 32],
        nullifier_e,
        qif_root_prev: qif,
        qif_root_curr: qif,
        s_start: start,
        s_end: end,
        used_in: 0,
        used_out: 1,
        cohort_size: if profile == 3 { 48 } else { 0 },
    }
}

fn wire(st: &EpochStatement) -> Vec<u8> {
    let proof = prove_epoch(st, &[SlotKind::Fold { delta_mb: 1 }]).unwrap();
    Frame::build(st, proof, Some(48), true, None).unwrap()
}

fn l3_trust() -> RollupTrust<'static> {
    RollupTrust::L3Cohort { root: &[3; 32], size: 48 }
}

fn encode(frame: &Frame) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(frame, &mut out).unwrap();
    out
}

#[test]
fn l3_refuses_nonzero_cover_and_ignored_suffix_with_valid_proof() {
    let original = wire(&statement(3, 1, 1));
    Frame::verify_with_trust(&original, &[vk_digest()], l3_trust()).unwrap();
    let mut nonzero = Frame::decode(&original).unwrap();
    assert!(!nonzero.padding.is_empty());
    nonzero.padding[0] = 0x5a;
    let nonzero_wire = encode(&nonzero);
    assert_eq!(nonzero_wire.len(), L3_FRAME_BYTES);
    assert!(Frame::verify_with_trust(&nonzero_wire, &[vk_digest()], l3_trust())
        .unwrap_err().is("ROLLUP_NONZERO_PADDING"));

    // Preserve total normative size: move one byte from the serialized padding
    // to a second CBOR item. The original proof and every statement field stay
    // byte-for-byte intact, so the old decoder would accept this ignored data.
    let mut suffix = Frame::decode(&original).unwrap();
    suffix.padding.pop().unwrap();
    let mut suffix_wire = encode(&suffix);
    suffix_wire.push(0);
    assert_eq!(suffix_wire.len(), L3_FRAME_BYTES);
    assert!(Frame::verify_with_trust(&suffix_wire, &[vk_digest()], l3_trust())
        .unwrap_err().is("ROLLUP_TRAILING_BYTES"));
    Frame::verify_with_trust(&original, &[vk_digest()], l3_trust()).unwrap();
}

#[test]
fn all_proof_codecs_refuse_inner_suffix_with_valid_and_constant_size_l3_controls() {
    let slots = [SlotKind::Fold { delta_mb: 1 }];
    let legacy = statement(3, 1, 1);
    let legacy_proof = prove_epoch(&legacy, &slots).unwrap();
    let seeded_proof = prove_epoch_hiding(&legacy, &slots, 0xabc).unwrap();
    let mut private = legacy.clone();
    private.vk_digest = hiding_vk_digest();
    let private_proof = prove_epoch_private(&private, &slots).unwrap();

    verify_epoch(&legacy, &legacy_proof).unwrap();
    verify_epoch_hiding(&legacy, &seeded_proof, 0xabc).unwrap();
    verify_epoch_private(&private, &private_proof).unwrap();
    // One extra CBOR item and a recognizable synthetic payload must both be
    // rejected by the actual inner proof decoder, not by failed STARK checks.
    for suffix in [&[0u8][..], &b"synthetic-inner-canary"[..]] {
        let mut hostile = legacy_proof.clone();
        hostile.extend_from_slice(suffix);
        assert!(verify_epoch(&legacy, &hostile).unwrap_err().is("PROOF_DECODE"));
        let mut hostile = seeded_proof.clone();
        hostile.extend_from_slice(suffix);
        assert!(verify_epoch_hiding(&legacy, &hostile, 0xabc)
            .unwrap_err().is("PROOF_DECODE"));
        let mut hostile = private_proof.clone();
        hostile.extend_from_slice(suffix);
        assert!(verify_epoch_private(&private, &hostile)
            .unwrap_err().is("PROOF_DECODE"));
    }

    for (st, proof) in [(&legacy, legacy_proof), (&private, private_proof)] {
        let original = Frame::build(st, proof, Some(48), true, None).unwrap();
        Frame::verify_with_trust(&original, &[st.vk_digest], l3_trust()).unwrap();
        let mut hostile = Frame::decode(&original).unwrap();
        let original_proof = hostile.proof.clone();
        hostile.proof.extend_from_slice(b"synthetic-inner-canary");
        hostile.proof_bytes_len = hostile.proof.len() as u64;
        // Account for encoded lengths as well as the added payload. Retain
        // exact normative total size and zero padding so the inner parser is
        // the only expected refusal boundary.
        let enlarged = encode(&hostile).len();
        let extra = enlarged.checked_sub(original.len()).unwrap();
        hostile.padding.truncate(hostile.padding.len() - extra);
        let hostile_wire = encode(&hostile);
        assert_eq!(hostile_wire.len(), L3_FRAME_BYTES);
        let decoded = Frame::decode(&hostile_wire).unwrap();
        assert_eq!(decoded.proof_bytes_len, decoded.proof.len() as u64);
        assert!(decoded.proof.starts_with(&original_proof));
        assert!(decoded.padding.iter().all(|byte| *byte == 0));
        assert!(Frame::verify_with_trust(&hostile_wire, &[st.vk_digest], l3_trust())
            .unwrap_err().is("PROOF_DECODE"));
        Frame::verify_with_trust(&original, &[st.vk_digest], l3_trust()).unwrap();
    }
}

fn add_unknown(value: &mut ciborium::value::Value, component: &str) {
    use ciborium::value::Value;
    let Value::Map(top) = value else { panic!("frame map") };
    let target = if component == "frame" {
        top
    } else {
        let (_, nested) = top.iter_mut().find(|(key, _)| key.as_text() == Some(component)).unwrap();
        let Value::Map(map) = nested else { panic!("nested map") };
        map
    };
    target.push((Value::Text("unapproved_payload".into()), Value::Bytes(b"synthetic-canary".to_vec())));
}

#[test]
fn l3_refuses_unrecognized_frame_public_input_and_fri_fields() {
    use ciborium::value::Value;
    let original = wire(&statement(3, 1, 1));
    Frame::verify_with_trust(&original, &[vk_digest()], l3_trust()).unwrap();
    for component in ["frame", "public_inputs", "fri"] {
        let mut value: Value = ciborium::from_reader(original.as_slice()).unwrap();
        add_unknown(&mut value, component);
        // Reduce the zero cover by exactly the additional CBOR field length;
        // the attack must have the same total length as the valid control.
        let mut enlarged = Vec::new();
        ciborium::into_writer(&value, &mut enlarged).unwrap();
        let extra = enlarged.len() - original.len();
        let Value::Map(top) = &mut value else { panic!("frame map") };
        let (_, padding) = top.iter_mut().find(|(key, _)| key.as_text() == Some("padding")).unwrap();
        let Value::Bytes(bytes) = padding else { panic!("padding bytes") };
        bytes.truncate(bytes.len() - extra);
        let mut hostile = Vec::new();
        ciborium::into_writer(&value, &mut hostile).unwrap();
        assert_eq!(hostile.len(), L3_FRAME_BYTES, "{component}");
        assert!(Frame::verify_with_trust(&hostile, &[vk_digest()], l3_trust())
            .unwrap_err().is("ROLLUP_DECODE"), "{component}");
    }
}

#[test]
fn series_refuses_u64_wrap_but_accepts_terminal_max_and_healthy_boundary() {
    let first = statement(3, u64::MAX, u64::MAX);
    let first_wire = wire(&first);
    // The largest representable singleton is a valid terminal span.
    Frame::verify_series_with_trust(&[&first_wire], &[vk_digest()], l3_trust()).unwrap();
    let mut wrapped = statement(3, 0, 0);
    wrapped.j_prev = first.j_curr;
    wrapped.used_in = 1;
    wrapped.used_out = 2;
    let wrapped_wire = wire(&wrapped);
    assert!(Frame::verify_series_with_trust(
        &[&first_wire, &wrapped_wire], &[vk_digest()], l3_trust(),
    ).unwrap_err().is("SLOT_GAP"));

    let before = statement(3, u64::MAX - 1, u64::MAX - 1);
    let mut terminal = statement(3, u64::MAX, u64::MAX);
    terminal.j_prev = before.j_curr;
    terminal.used_in = 1;
    terminal.used_out = 2;
    Frame::verify_series_with_trust(
        &[wire(&before), wire(&terminal)], &[vk_digest()], l3_trust(),
    ).unwrap();
}

fn fold(seq: u64) -> SlotWitness {
    SlotWitness::Fold { seq, scrubbed: b"[REDACTED]".to_vec(), qif_delta_mb: 1 }
}

#[test]
fn native_prover_refuses_wrapped_spans_and_series_without_panicking() {
    let key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng).verifying_key();
    let keys = TombstoneKeys { k703: key, k704: key };
    let public = EpochPublic { profile: 2, policy_blake3: [1; 32], tuf_snapshot_root: [2; 32], j_prev: hash_bytes(b"genesis", b"") };
    let make = |slots: &[SlotWitness]| prove_rollup(
        &public, &[7; 32], "synthetic-epoch", slots, &[], &keys,
        None, Some(vec!["accounting-only-fixture".into()]), false,
    );
    assert!(make(&[fold(u64::MAX), fold(0)]).unwrap_err().is("SLOT_SPAN_OVERFLOW"));
    let terminal = make(&[fold(u64::MAX)]).unwrap();
    Frame::verify(&terminal, &[hiding_vk_digest()]).unwrap();
    let chunks = [
        EpochChunk { slots: vec![fold(u64::MAX)], journal_lines: vec![] },
        EpochChunk { slots: vec![fold(0)], journal_lines: vec![] },
    ];
    assert!(prove_rollup_series(
        &public, &[7; 32], "synthetic-epoch", &chunks, &keys,
        None, Some(vec!["accounting-only-fixture".into()]), false,
    ).unwrap_err().is("SLOT_GAP"));
    let healthy = [
        EpochChunk { slots: vec![fold(u64::MAX - 1)], journal_lines: vec![] },
        EpochChunk { slots: vec![fold(u64::MAX)], journal_lines: vec![] },
    ];
    let frames = prove_rollup_series(
        &public, &[7; 32], "synthetic-epoch", &healthy, &keys,
        None, Some(vec!["accounting-only-fixture".into()]), false,
    ).unwrap();
    Frame::verify_series(&frames, &[hiding_vk_digest()]).unwrap();
}

#[test]
fn json_view_preserves_actual_legacy_and_production_versions() {
    let legacy = Frame::decode(&wire(&statement(3, 1, 1))).unwrap();
    assert_eq!(legacy.json_view()["v"], 1);
    Frame::validate_json_view(&legacy.json_view()).unwrap();
    let mut private = statement(3, 1, 1);
    private.vk_digest = hiding_vk_digest();
    let proof = prove_epoch_private(&private, &[SlotKind::Fold { delta_mb: 1 }]).unwrap();
    let bytes = Frame::build(&private, proof, Some(48), true, None).unwrap();
    let private = Frame::verify_with_trust(&bytes, &[hiding_vk_digest()], l3_trust()).unwrap();
    assert_eq!(private.v, 2);
    assert_eq!(private.json_view()["v"], 2);
    Frame::validate_json_view(&private.json_view()).unwrap();
}

#[test]
fn manifest_digest_refuses_length_aliases_and_invalid_hex() {
    for mut manifest in [VkManifestV1::default(), VkManifestV1::production_hiding()] {
        let expected = manifest.vk_digest_bytes().unwrap();
        assert_eq!(expected.len(), 32);
        for text in [String::new(), "00".repeat(31), "00".repeat(33)] {
            manifest.vk_digest = text;
            assert_eq!(manifest.vk_digest_bytes().unwrap_err(), hex::FromHexError::InvalidStringLength);
        }
        for text in ["0".to_string(), "gg".repeat(32)] {
            manifest.vk_digest = text;
            assert!(manifest.vk_digest_bytes().is_err());
        }
        manifest.vk_digest = hex::encode(expected);
        assert_eq!(manifest.vk_digest_bytes().unwrap(), expected);
    }
}
