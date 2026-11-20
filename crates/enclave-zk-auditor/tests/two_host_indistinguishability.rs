//! Two-host frame-shape regression; this is not an indistinguishability proof.
//!
//! Asserts that two distinct hosts in the same fleet cohort (N >= 32) produce
//! L3 heartbeat cover frames of identical wire length (327,680 bytes), committing
//! to the exact same cohort root `R_fleet_pk`, carrying zero identifying host keys or
//! batch signatures. Public sequence numbers still distinguish these frames.
//! A byte histogram does not measure adversarial distinguisher advantage.

use enclave_core::poseidon2::hash_bytes;
use enclave_zk_auditor::cohort::{leaf, CohortTree};
use enclave_zk_auditor::relation::{prove_rollup, EpochPublic, HardwareWitness, SlotWitness};
use enclave_zk_auditor::rollup::{ComplianceRollupProofV1, L3_FRAME_BYTES};
use enclave_zk_auditor::tombstone::TombstoneKeys;
use enclave_zk_auditor::zk::manifest::VkManifestV1;

fn cohort(n: usize, member: usize) -> HardwareWitness {
    let keys: Vec<(Vec<u8>, Vec<u8>)> = (0..n)
        .map(|i| {
            (
                format!("cohort-sep-device-{i:03}").into_bytes(),
                format!("cohort-yk-device-{i:03}").into_bytes(),
            )
        })
        .collect();
    let tree = CohortTree::build(keys.iter().map(|(a, b)| leaf(a, b)).collect()).unwrap();
    HardwareWitness {
        pk_sep: keys[member].0.clone(),
        pk_yk: keys[member].1.clone(),
        path: tree.path(member).unwrap(),
        root: tree.root(),
        cohort_size: tree.size(),
    }
}

fn shannon_entropy(data: &[u8]) -> f64 {
    let mut freq = [0usize; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut h = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / n;
            h -= p * p.log2();
        }
    }
    h
}

fn total_variation_distance(data_a: &[u8], data_b: &[u8]) -> f64 {
    let mut freq_a = [0f64; 256];
    let mut freq_b = [0f64; 256];
    for &b in data_a {
        freq_a[b as usize] += 1.0;
    }
    for &b in data_b {
        freq_b[b as usize] += 1.0;
    }
    let n_a = data_a.len() as f64;
    let n_b = data_b.len() as f64;
    let mut tv = 0.0;
    for i in 0..256 {
        tv += ((freq_a[i] / n_a) - (freq_b[i] / n_b)).abs();
    }
    tv * 0.5
}

#[test]
fn test_two_host_heartbeat_indistinguishability() {
    const COHORT_SIZE: usize = 32;

    // Host A setup: member 3 of 32
    let hw_a = cohort(COHORT_SIZE, 3);
    let id_enclave_a = [0x11u8; 32];
    let entity_a = "corp:fleet-node-03";

    // Host B setup: member 19 of 32
    let hw_b = cohort(COHORT_SIZE, 19);
    let id_enclave_b = [0x22u8; 32];
    let entity_b = "corp:fleet-node-19";

    // Common cohort root
    assert_eq!(hw_a.root, hw_b.root);
    assert_eq!(hw_a.cohort_size, hw_b.cohort_size);

    let public = EpochPublic {
        profile: 3, // L3
        policy_blake3: [0x55; 32],
        tuf_snapshot_root: [0x66; 32],
        j_prev: hash_bytes(b"genesis", b""),
    };

    let dummy_slot_a = SlotWitness::Fold {
        seq: 100,
        scrubbed: b"{\"cover\":true}".to_vec(),
        qif_delta_mb: 0,
    };
    let dummy_slot_b = SlotWitness::Fold {
        seq: 500,
        scrubbed: b"{\"cover\":true}".to_vec(),
        qif_delta_mb: 0,
    };
    let dummy_lines = vec![b"{\"cover\":true}".to_vec()];

    let z_a = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng).verifying_key();
    let keys_a = TombstoneKeys {
        k703: z_a,
        k704: z_a,
    };

    let z_b = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng).verifying_key();
    let keys_b = TombstoneKeys {
        k703: z_b,
        k704: z_b,
    };

    // 1. Generate L3 heartbeat frame from Host A
    let wire_a = prove_rollup(
        &public,
        &id_enclave_a,
        entity_a,
        &[dummy_slot_a],
        &dummy_lines,
        &keys_a,
        Some(&hw_a),
        None, // Anonymous: zero batch signatures
        true, // heartbeat: true
    )
    .expect("Host A prove_rollup must succeed");

    // 2. Generate L3 heartbeat frame from Host B
    let wire_b = prove_rollup(
        &public,
        &id_enclave_b,
        entity_b,
        &[dummy_slot_b],
        &dummy_lines,
        &keys_b,
        Some(&hw_b),
        None, // Anonymous: zero batch signatures
        true, // heartbeat: true
    )
    .expect("Host B prove_rollup must succeed");

    // Property 1: Identical fixed wire byte length (320 KiB).
    assert_eq!(wire_a.len(), L3_FRAME_BYTES);
    assert_eq!(wire_b.len(), L3_FRAME_BYTES);
    assert_eq!(wire_a.len(), wire_b.len());

    // Property 2: Identical committed cohort root and cohort size
    let manifest = VkManifestV1::production_hiding();
    let vk_digest_bytes = manifest.vk_digest_bytes().unwrap();

    let frame_a = ComplianceRollupProofV1::verify(&wire_a, &[vk_digest_bytes])
        .expect("Host A frame must verify");
    let frame_b = ComplianceRollupProofV1::verify(&wire_b, &[vk_digest_bytes])
        .expect("Host B frame must verify");

    assert_eq!(frame_a.profile, 3);
    assert_eq!(frame_b.profile, 3);
    assert_eq!(frame_a.heartbeat, Some(true));
    assert_eq!(frame_b.heartbeat, Some(true));
    assert_eq!(frame_a.cohort_size, Some(COHORT_SIZE as u64));
    assert_eq!(frame_b.cohort_size, Some(COHORT_SIZE as u64));
    assert_eq!(
        frame_a.public_inputs.R_fleet_pk,
        frame_b.public_inputs.R_fleet_pk
    );

    // Property 3: No literal host key encodings or batch signatures in the frame.
    // Public sequence numbers differ: these frames are distinguishable even
    // when their byte histograms happen to be close.
    assert_ne!(frame_a.s_start, frame_b.s_start);
    assert!(frame_a.hardware_batch_anchor_sigs.is_none());
    assert!(frame_b.hardware_batch_anchor_sigs.is_none());

    // Check that neither frame contains host-specific raw keys as substrings
    assert!(!wire_a
        .windows(hw_a.pk_sep.len())
        .any(|w| w == hw_a.pk_sep.as_slice()));
    assert!(!wire_a
        .windows(hw_a.pk_yk.len())
        .any(|w| w == hw_a.pk_yk.as_slice()));
    assert!(!wire_a
        .windows(id_enclave_a.len())
        .any(|w| w == id_enclave_a.as_slice()));

    assert!(!wire_b
        .windows(hw_b.pk_sep.len())
        .any(|w| w == hw_b.pk_sep.as_slice()));
    assert!(!wire_b
        .windows(hw_b.pk_yk.len())
        .any(|w| w == hw_b.pk_yk.as_slice()));
    assert!(!wire_b
        .windows(id_enclave_b.len())
        .any(|w| w == id_enclave_b.as_slice()));

    // Histogram diagnostics only; no statistical privacy conclusion follows.
    let tv_dist = total_variation_distance(&wire_a, &wire_b);
    let entropy_a = shannon_entropy(&wire_a);
    let entropy_b = shannon_entropy(&wire_b);
    println!("Wire bytes length: {} bytes", wire_a.len());
    println!(
        "Host A entropy: {:.4} bits/byte, Host B entropy: {:.4} bits/byte",
        entropy_a, entropy_b
    );
    println!(
        "Byte histogram distance (not distinguisher advantage): {:.6}",
        tv_dist
    );
}
