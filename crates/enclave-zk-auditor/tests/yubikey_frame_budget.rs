//! YKD-10 complete CBOR budget. Synthetic proof bytes exercise the production
//! codec, not STARK validity, hardware membership, privacy, or native resources.
use enclave_zk_auditor::zk::manifest::VkManifestV1;
use enclave_zk_auditor::{
    rollup::{ComplianceRollupProofV1 as Frame, L3_FRAME_BYTES, MAX_FRAME_BYTES},
    zk::engine::EpochStatement,
};

fn statement(profile: u8) -> EpochStatement {
    EpochStatement {
        vk_digest: [1; 32], profile, policy_blake3: [2; 32],
        tuf_snapshot_root: [3; 32], qif_cap_mb: 12_000,
        r_fleet_pk: [4; 32], j_prev: [5; 32], j_curr: [6; 32],
        nullifier_e: [7; 32], qif_root_prev: [8; 32], qif_root_curr: [9; 32],
        s_start: 1, s_end: 1, used_in: 0, used_out: 1, cohort_size: 48,
    }
}

fn l2(size: usize, anchors: Vec<String>) -> enclave_core::error::EnclaveResult<Vec<u8>> {
    Frame::build(&statement(2), vec![0xaa; size], None, false, Some(anchors))
}

#[test]
fn l2_final_bytes_include_headers_and_anchor_cost_at_the_boundary() {
    // A large anchor makes it impossible to mistake a proof-only bound for the
    // full wire contract. This is an opaque codec fixture, not a valid signature.
    let anchors = vec!["ab".repeat(3360)];
    let small = l2(65_536, anchors.clone()).unwrap();
    let overhead = small.len() - 65_536;
    let at = MAX_FRAME_BYTES - overhead;
    let bytes = l2(at, anchors.clone()).unwrap();
    assert_eq!(bytes.len(), MAX_FRAME_BYTES);
    Frame::decode(&bytes).unwrap();
    assert_eq!(l2(at - 1, anchors.clone()).unwrap().len(), MAX_FRAME_BYTES - 1);
    assert!(l2(at + 1, anchors).unwrap_err().is("ROLLUP_FRAME_TOO_LARGE"));
    assert!(l2(MAX_FRAME_BYTES, vec!["ab".into()]).unwrap_err().is("ROLLUP_FRAME_TOO_LARGE"));
}

#[test]
fn decoder_rejects_oversize_before_cbor_and_validator_rejects_false_length() {
    let bytes = l2(256, vec!["ab".into()]).unwrap();
    let frame = Frame::decode(&bytes).unwrap();
    assert!(frame.validate_frame(MAX_FRAME_BYTES + 1).unwrap_err().is("ROLLUP_FRAME_TOO_LARGE"));
    // Previously the decoder admitted up to 640 KiB. Even malformed input above
    // the contract cap now refuses before entering the CBOR parser.
    assert!(Frame::decode(&vec![0xff; MAX_FRAME_BYTES + 1]).unwrap_err().is("ROLLUP_FRAME_TOO_LARGE"));
    let mut unknown = frame;
    unknown.v = 3;
    let mut encoded = Vec::new();
    ciborium::into_writer(&unknown, &mut encoded).unwrap();
    assert!(Frame::decode(&encoded).unwrap_err().is("ROLLUP_HEADER"));
}

#[test]
fn l3_padding_accounts_for_cbor_length_transitions_and_oversize_proof() {
    for size in [1, 23, 24, 255, 256, 65_535, 65_536, MAX_FRAME_BYTES - 2048] {
        let bytes = Frame::build(&statement(3), vec![0xaa; size], Some(48), true, None).unwrap();
        assert_eq!(bytes.len(), L3_FRAME_BYTES);
        let frame = Frame::decode(&bytes).unwrap();
        assert_eq!(frame.proof.len(), size);
        assert!(frame.padding.iter().all(|byte| *byte == 0));
        assert_eq!(frame.fri.queries, 84);
        assert_eq!(frame.fri.pow_bits, 16);
    }
    assert!(Frame::build(&statement(3), vec![0xaa; MAX_FRAME_BYTES], Some(48), true, None).is_err());
}

#[test]
fn json_descriptor_cannot_claim_free_overhead_or_an_oversize_l2_frame() {
    let bytes = l2(256, vec!["ab".into()]).unwrap();
    let mut view = Frame::decode(&bytes).unwrap().json_view();
    Frame::validate_json_view(&view).unwrap();
    view["padded_frame_bytes"] = serde_json::json!(MAX_FRAME_BYTES + 1);
    assert!(Frame::validate_json_view(&view).unwrap_err().is("ROLLUP_FRAME_TOO_LARGE"));
    view["padded_frame_bytes"] = serde_json::json!(MAX_FRAME_BYTES);
    view["proof_bytes_len"] = serde_json::json!(MAX_FRAME_BYTES);
    assert!(Frame::validate_json_view(&view).unwrap_err().is("ROLLUP_JSON_OVERHEAD"));
}

#[test]
fn manifest_version_and_security_parameter_mutations_refuse() {
    let valid = VkManifestV1::production_hiding();
    valid.validate_supported().unwrap();
    for field in ["schema_version", "air_domain", "num_queries", "max_proof_bytes"] {
        let mut value = serde_json::to_value(&valid).unwrap();
        value[field] = if field == "num_queries" {serde_json::json!(42)}
            else if field == "max_proof_bytes" {serde_json::json!(655360)}
            else {serde_json::json!("unsupported")};
        assert!(VkManifestV1::from_json_bytes(&serde_json::to_vec(&value).unwrap()).unwrap()
            .validate_supported().unwrap_err().is("ROLLUP_MANIFEST_UNSUPPORTED"));
    }
    let mut value = serde_json::to_value(valid).unwrap();
    value["unreviewed_parameter"] = serde_json::json!(true);
    assert!(VkManifestV1::from_json_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
}
