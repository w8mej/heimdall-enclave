//! Bao tree operations and outboard verification (FS-702 §3.1, GAP-19, D-19a).
//!
//! depot uses Bao trees with 16 KiB leaves (chunk group = 16 KiB, block size chunk log 4)
//! and outboard storage for content-addressed verification.
//!
//! Plaintext Bao roots serve as the invariant `cas://blake3-bao-v1/<hex64>` identifiers,
//! while `transport_ciphertext_bao_root` verifies encrypted transport streams.

use std::io::Cursor;

use bao_tree::io::outboard::PreOrderMemOutboard;
use bao_tree::io::sync::{encode_ranges, DecodeResponseIter};
use bao_tree::io::BaoContentItem;
use bao_tree::{BaoTree, BlockSize, ChunkRanges};
use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};

/// 16 KiB leaves: 16 BLAKE3 chunks per leaf ($2^4 = 16$).
pub const CHUNK_LOG: u8 = 4;
/// Leaf size in bytes: 16 KiB.
pub const LEAF_SIZE: usize = 16 * 1024;

/// Block size for depot Bao trees (16 KiB).
pub fn block_size() -> BlockSize {
    BlockSize::from_chunk_log(CHUNK_LOG)
}

/// Compute the Bao root (hex-encoded 64 chars) over data.
pub fn bao_root(data: &[u8]) -> String {
    let outboard = PreOrderMemOutboard::create(data, block_size());
    outboard.root.to_hex().to_string()
}

/// Compute the Bao root and serialized outboard tree (with 8-byte length prefix).
pub fn create_outboard(data: &[u8]) -> (String, Vec<u8>) {
    let outboard = PreOrderMemOutboard::create(data, block_size());
    let root = outboard.root.to_hex().to_string();
    let bytes = outboard.into_inner_with_prefix();
    (root, bytes)
}

/// Encode full data stream into Bao encoded format (parents + leaves) for streaming.
pub fn encode_bao_stream(data: &[u8]) -> EnclaveResult<Vec<u8>> {
    let outboard = PreOrderMemOutboard::create(data, block_size());
    let all = ChunkRanges::all();
    let mut encoded = Vec::new();
    encode_ranges(data, &outboard, &all, &mut encoded)
        .map_err(|e| err!(EIO, "BAO_ENCODE", "{e}"))?;
    Ok(encoded)
}

/// Incrementally verify a Bao stream against an expected Bao root.
/// Returns the verified leaves (slices) in order, or fails immediately on any
/// parent hash or leaf slice corruption without buffering further unverified bytes.
pub fn verify_bao_stream(
    expected_root_hex: &str,
    total_size: u64,
    encoded_stream: &[u8],
) -> EnclaveResult<Vec<Vec<u8>>> {
    if expected_root_hex.len() != 64 {
        fail!(EINVAL, "BAO_ROOT_LEN", "expected 64 hex characters");
    }
    let expected_hash = bao_tree::blake3::Hash::from_hex(expected_root_hex)
        .map_err(|e| err!(EINVAL, "BAO_ROOT_HEX", "{e}"))?;

    let tree = BaoTree::new(total_size, block_size());
    let all = ChunkRanges::all();
    let cursor = Cursor::new(encoded_stream);
    let iter = DecodeResponseIter::new(expected_hash, tree, cursor, &all);

    let mut slices = Vec::new();
    for item in iter {
        let content_item = item.map_err(|e| err!(EACCES, "BAO_SLICE_CORRUPT", "{e}"))?;
        match content_item {
            BaoContentItem::Parent(_) => {
                // Parent hash node verified by DecodeResponseIter
            }
            BaoContentItem::Leaf(leaf) => {
                slices.push(leaf.data.to_vec());
            }
        }
    }
    Ok(slices)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bao_root_and_outboard() {
        let data = b"hello depot Bao";
        let r = bao_root(data);
        let b3 = blake3::hash(data).to_hex().to_string();
        assert_eq!(r, b3);
        assert_eq!(r.len(), 64);
        let (r2, ob) = create_outboard(data);
        assert_eq!(r, r2);
        assert!(!ob.is_empty());

        let large_data = vec![0x99u8; 100 * 1024];
        let r_large = bao_root(&large_data);
        let b3_large = blake3::hash(&large_data).to_hex().to_string();
        println!("large bao_root: {r_large}");
        println!("large blake3:   {b3_large}");
        assert_eq!(r_large, b3_large);
    }

    #[test]
    fn test_stream_verify_clean() {
        // Multi-slice data (> 16 KiB so we have multiple leaves and parent nodes)
        let data = vec![0x42u8; 40 * 1024]; // 40 KiB = 3 slices (16 + 16 + 8)
        let root = bao_root(&data);
        let encoded = encode_bao_stream(&data).expect("encode");

        let slices = verify_bao_stream(&root, data.len() as u64, &encoded).expect("verify");
        let reconstructed: Vec<u8> = slices.into_iter().flatten().collect();
        assert_eq!(reconstructed, data);
    }

    #[test]
    fn test_stream_verify_corrupted_slice() {
        let data = vec![0x7au8; 64 * 1024]; // 64 KiB = 4 slices
        let root = bao_root(&data);
        let mut encoded = encode_bao_stream(&data).expect("encode");

        // Flip a byte in the encoded stream
        let last_idx = encoded.len() - 10;
        encoded[last_idx] ^= 0xff;

        let res = verify_bao_stream(&root, data.len() as u64, &encoded);
        assert!(res.is_err());
        let err_str = format!("{:?}", res.err().unwrap());
        assert!(err_str.contains("BAO_SLICE_CORRUPT"));
    }

    #[test]
    fn test_stream_verify_truncated() {
        let data = vec![0x55u8; 32 * 1024];
        let root = bao_root(&data);
        let encoded = encode_bao_stream(&data).expect("encode");

        // Truncate stream
        let truncated = &encoded[..encoded.len() / 2];
        let res = verify_bao_stream(&root, data.len() as u64, truncated);
        assert!(res.is_err());
    }

    #[test]
    fn test_stream_verify_wrong_root() {
        let data = vec![0x33u8; 20 * 1024];
        let wrong_root = "0".repeat(64);
        let encoded = encode_bao_stream(&data).expect("encode");

        let res = verify_bao_stream(&wrong_root, data.len() as u64, &encoded);
        assert!(res.is_err());
    }

    #[test]
    fn stream_verification_rejects_corruption_across_parents_and_leaves() {
        // More than three chunk groups ensures both parent records and leaves
        // are checked by the synchronous decoder, without upstream `validate`.
        let data: Vec<u8> = (0..3 * LEAF_SIZE + 127)
            .map(|i| (i % 251) as u8)
            .collect();
        let root = blake3::hash(&data).to_hex().to_string();
        let encoded = encode_bao_stream(&data).expect("encode");
        let clean = verify_bao_stream(&root, data.len() as u64, &encoded).expect("verify");
        assert_eq!(clean.into_iter().flatten().collect::<Vec<_>>(), data);

        for offset in (0..encoded.len()).step_by(1024).chain([encoded.len() - 1]) {
            let mut damaged = encoded.clone();
            damaged[offset] ^= 1;
            let error = verify_bao_stream(&root, data.len() as u64, &damaged)
                .expect_err("corrupt parent or leaf must not produce verified output");
            assert!(
                format!("{error:?}").contains("BAO_SLICE_CORRUPT"),
                "unexpected failure at encoded offset {offset}: {error:?}"
            );
        }
    }

    #[test]
    fn stream_verification_binds_the_declared_size_at_group_boundaries() {
        for size in [1, LEAF_SIZE - 1, LEAF_SIZE, LEAF_SIZE + 1, 2 * LEAF_SIZE + 1] {
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let root = blake3::hash(&data).to_hex().to_string();
            let encoded = encode_bao_stream(&data).expect("encode");
            let clean = verify_bao_stream(&root, size as u64, &encoded).expect("verify");
            assert_eq!(clean.into_iter().flatten().collect::<Vec<_>>(), data);
            assert!(verify_bao_stream(&root, size as u64 + 1, &encoded).is_err());
            if size > 1 {
                assert!(verify_bao_stream(&root, size as u64 - 1, &encoded).is_err());
            }
        }
    }

    #[test]
    fn test_bao_standard_test_vectors() {
        // Standard BLAKE3/Bao sequence: input[i] = (i % 251) as u8
        let test_sizes = [
            0, 1, 1023, 1024, 1025, 16383, 16384, 16385, 32768, 65536, 100000,
        ];
        for &size in &test_sizes {
            let input: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let r = bao_root(&input);
            let b3 = blake3::hash(&input).to_hex().to_string();
            assert_eq!(r, b3, "root mismatch for size {size}");

            let (r_ob, ob_bytes) = create_outboard(&input);
            assert_eq!(r_ob, b3);
            if size > 0 {
                assert!(!ob_bytes.is_empty());
                let encoded = encode_bao_stream(&input).expect("encode");
                let slices = verify_bao_stream(&r, input.len() as u64, &encoded).expect("verify");
                let reassembled: Vec<u8> = slices.into_iter().flatten().collect();
                assert_eq!(reassembled, input, "roundtrip mismatch for size {size}");
            }
        }
    }
}
