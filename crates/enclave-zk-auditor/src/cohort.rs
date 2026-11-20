//! ADR-016 fleet cohort Merkle tree `R_fleet_pk` over
//! `(pk_SEP, pk_YK)` leaves (Poseidon2, cohort `>= 32`). In `L3` frames carry
//! **zero** hardware signatures or key identifiers; membership is checked over
//! the private witness by the prover. Unique leaves do not establish unique
//! physical hosts, trusted fleet enrollment, or verifier-side membership (F78).

use enclave_core::error::EnclaveResult;
use enclave_core::fail;
use enclave_core::poseidon2::{compress, hash_bytes, Poseidon2Digest};

/// Minimum cohort size.
pub const MIN_COHORT: usize = 32;
/// Sizes must have a canonical single-limb KoalaBear representation.
pub const MAX_COHORT: usize = enclave_core::poseidon2::KOALABEAR_P as usize - 1;
const LEAF: &[u8] = b"MCPMac-FleetLeaf-v1";
const NODE: &[u8] = b"MCPMac-FleetNode-v1";
const COHORT_ROOT_TAG: &[u8] = b"MCPMac-FleetCohortRoot-v1";

/// Leaf digest of an enrolled workstation.
pub fn leaf(pk_sep: &[u8], pk_yk: &[u8]) -> Poseidon2Digest {
    let mut b = (pk_sep.len() as u32).to_be_bytes().to_vec();
    b.extend_from_slice(pk_sep);
    b.extend_from_slice(pk_yk);
    hash_bytes(LEAF, &b)
}

/// Commit cohort size in the tree root (D-23e).
pub fn commit_cohort_size_to_root(raw_root: &Poseidon2Digest, size: usize) -> Poseidon2Digest {
    let mut size_limbs = [0u32; 8];
    size_limbs[0] = size as u32;
    compress(COHORT_ROOT_TAG, raw_root, &Poseidon2Digest(size_limbs))
}

/// The cohort tree.
#[derive(Debug, Clone)]
pub struct CohortTree {
    levels: Vec<Vec<Poseidon2Digest>>,
    size: usize,
}

/// A membership path.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MembershipPath {
    /// Leaf index.
    pub index: usize,
    /// Siblings bottom-up.
    pub siblings: Vec<Poseidon2Digest>,
}

impl CohortTree {
    /// Build from leaves (padded with zero digests to a power of two).
    pub fn build(leaves: Vec<Poseidon2Digest>) -> EnclaveResult<Self> {
        if leaves.len() < MIN_COHORT {
            fail!(
                EPERM,
                "COHORT_TOO_SMALL",
                "{} < {MIN_COHORT}: L3 rollups would identify the workstation",
                leaves.len()
            );
        }
        if leaves.len() > MAX_COHORT {
            fail!(E2BIG, "COHORT_TOO_LARGE");
        }
        let unique: std::collections::BTreeSet<_> = leaves.iter().map(|l| l.0).collect();
        if unique.len() != leaves.len() {
            fail!(EINVAL, "COHORT_DUPLICATE_LEAF");
        }
        let size = leaves.len();
        let mut l = leaves;
        l.resize(size.next_power_of_two(), Poseidon2Digest::ZERO);
        let mut levels = vec![l];
        while levels.last().is_some_and(|x| x.len() > 1) {
            let prev = levels.last().cloned().unwrap_or_default();
            levels.push(
                prev.chunks(2)
                    .map(|c| compress(NODE, &c[0], &c[1]))
                    .collect(),
            );
        }
        Ok(Self { levels, size })
    }
    /// Raw uncommitted tree root.
    pub fn raw_root(&self) -> Poseidon2Digest {
        self.levels
            .last()
            .and_then(|l| l.first().copied())
            .unwrap_or(Poseidon2Digest::ZERO)
    }
    /// Root with cohort size committed (D-23e).
    pub fn root(&self) -> Poseidon2Digest {
        commit_cohort_size_to_root(&self.raw_root(), self.size)
    }
    /// Root as 32 bytes.
    pub fn root_bytes(&self) -> [u8; 32] {
        digest_bytes(&self.root())
    }
    /// Cohort size.
    pub fn size(&self) -> usize {
        self.size
    }
    /// Path for `index`.
    pub fn path(&self, index: usize) -> EnclaveResult<MembershipPath> {
        if index >= self.size {
            fail!(EINVAL, "COHORT_INDEX");
        }
        let mut i = index;
        let mut s = Vec::new();
        for lvl in &self.levels[..self.levels.len() - 1] {
            s.push(lvl[i ^ 1]);
            i >>= 1;
        }
        Ok(MembershipPath { index, siblings: s })
    }
}

/// Verify membership of `leaf` under `root` with committed `cohort_size`.
pub fn verify_membership(
    root: &Poseidon2Digest,
    leaf: &Poseidon2Digest,
    p: &MembershipPath,
    cohort_size: usize,
) -> bool {
    if !(MIN_COHORT..=MAX_COHORT).contains(&cohort_size) || p.index >= cohort_size {
        return false;
    }
    let Some(width) = cohort_size.checked_next_power_of_two() else {
        return false;
    };
    if p.siblings.len() != width.trailing_zeros() as usize {
        return false;
    }
    let mut h = *leaf;
    let mut i = p.index;
    for s in &p.siblings {
        h = if i & 1 == 0 {
            compress(NODE, &h, s)
        } else {
            compress(NODE, s, &h)
        };
        i >>= 1;
    }
    let expected_root = commit_cohort_size_to_root(&h, cohort_size);
    &expected_root == root
}

/// 32-byte big-endian encoding of a digest's 8 limbs.
pub fn digest_bytes(d: &Poseidon2Digest) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, l) in d.0.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&l.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn membership_and_minimum_cohort() {
        let leaves: Vec<_> = (0..40u8).map(|i| leaf(&[i; 65], &[i; 32])).collect();
        let t = CohortTree::build(leaves.clone()).unwrap();
        for i in [0, 17, 39] {
            assert!(verify_membership(
                &t.root(),
                &leaves[i],
                &t.path(i).unwrap(),
                t.size(),
            ));
        }
        let outsider = leaf(&[99; 65], &[99; 32]);
        assert!(!verify_membership(
            &t.root(),
            &outsider,
            &t.path(3).unwrap(),
            t.size(),
        ));
        // Claiming forged cohort size fails verification
        assert!(!verify_membership(
            &t.root(),
            &leaves[0],
            &t.path(0).unwrap(),
            48, // forged size != 40
        ));
        assert!(CohortTree::build(leaves[..31].to_vec())
            .unwrap_err()
            .is("COHORT_TOO_SMALL"));
    }

    #[test]
    fn verifier_rejects_noncanonical_paths_and_padding_positions() {
        let leaves: Vec<_> = (0..40u8).map(|i| leaf(&[i], &[i])).collect();
        let tree = CohortTree::build(leaves.clone()).unwrap();
        let valid = tree.path(0).unwrap();
        let mut high_index = valid.clone();
        high_index.index += 1 << valid.siblings.len();
        assert!(!verify_membership(
            &tree.root(),
            &leaves[0],
            &high_index,
            40
        ));

        // The padding leaf really is in this tree, but is not a cohort member.
        let index = 40;
        let mut i = index;
        let siblings = tree.levels[..tree.levels.len() - 1]
            .iter()
            .map(|level| {
                let sibling = level[i ^ 1];
                i >>= 1;
                sibling
            })
            .collect();
        assert!(!verify_membership(
            &tree.root(),
            &Poseidon2Digest::ZERO,
            &MembershipPath { index, siblings },
            40,
        ));

        // Even a root made for a malformed depth must be rejected structurally.
        let empty = MembershipPath {
            index: 0,
            siblings: vec![],
        };
        let fake_root = commit_cohort_size_to_root(&leaves[0], 40);
        assert!(!verify_membership(&fake_root, &leaves[0], &empty, 40));
        for size in [0, 1, 31, usize::MAX] {
            assert!(!verify_membership(&tree.root(), &leaves[0], &valid, size));
        }
    }

    #[test]
    fn membership_binds_the_claimed_index_even_for_another_enrolled_leaf() {
        let leaves: Vec<_> = (0..40u8).map(|i| leaf(&[i; 65], &[i; 32])).collect();
        let tree = CohortTree::build(leaves.clone()).unwrap();
        for index in [0, 17, 39] {
            let path = tree.path(index).unwrap();
            for (other, value) in leaves.iter().enumerate() {
                assert_eq!(
                    verify_membership(&tree.root(), value, &path, tree.size()),
                    index == other
                );
            }
        }
        // Identical unframed concatenations name different key pairs.
        assert_ne!(leaf(&[1], &[2, 3]), leaf(&[1, 2], &[3]));
    }

    #[test]
    fn duplicate_leaves_do_not_inflate_the_cohort() {
        let one_host = leaf(b"same-sep", b"same-authenticator");
        assert!(CohortTree::build(vec![one_host; MIN_COHORT])
            .unwrap_err()
            .is("COHORT_DUPLICATE_LEAF"));
    }
}
