//! Native prover-side witness checks followed by an accounting range proof.
//!
//! PII scans, tombstone signatures, actual-slot/journal correspondence and L3
//! membership run on the proving host. The verifier cannot infer they ran from
//! the EpochAir proof. Only fold/tomb flags, sequence offsets and counter ranges
//! are constrained in that AIR; real journal, identity and tree relations are
//! absent. See zk/ASSURANCE.md and F78/F87. This is not the full R_epoch relation.

use enclave_core::audit::AUDIT_LINE_DOMAIN;
use enclave_core::error::EnclaveResult;
use enclave_core::fail;
use enclave_core::pii::scan;
use enclave_core::poseidon2::{compress, hash_bytes, Poseidon2Digest};

use crate::cohort::{digest_bytes, leaf, verify_membership, MembershipPath, MIN_COHORT};
use crate::rollup::{ComplianceRollupProofV1, QIF_CAP_MB};
use crate::tombstone::{Tombstone, TombstoneKeys};
use crate::zk::engine::{prove_epoch_private, hiding_vk_digest as vk_digest, EpochStatement, SlotKind};

/// Maximum slots per frame (FS-705 Rev 1.4, GAP-24).
/// Raised from 64 to 4,096 slots to allow a complete epoch to be proven in a single
/// constant-size proof under the revised 320 KiB frame budget (`MAX_PROOF_BYTES = 327_680`).
pub const MAX_SLOTS_PER_FRAME: usize = 4096;

const DOM_NULL: &[u8] = b"MCPMac-Nullifier-v1";
const DOM_JOURNAL: &[u8] = b"MCPMac-JournalFold-v1";

/// One slot of private witness.
#[derive(Debug, Clone)]
pub enum SlotWitness {
    /// Redaction fold.
    Fold {
        /// `rpc_seq_u64`.
        seq: u64,
        /// `D_scrub` (scrubbed egress payload).
        scrubbed: Vec<u8>,
        /// Millibits charged.
        qif_delta_mb: u32,
    },
    /// Tombstone.
    Tombstone(Tombstone),
}

impl SlotWitness {
    fn seq(&self) -> u64 {
        match self {
            SlotWitness::Fold { seq, .. } => *seq,
            SlotWitness::Tombstone(t) => t.slot,
        }
    }
}

/// `L3` hardware membership witness (private; never placed on the wire).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HardwareWitness {
    /// SEP public key (SEC1).
    #[serde(with = "serde_bytes")]
    pub pk_sep: Vec<u8>,
    /// YubiKey public key.
    #[serde(with = "serde_bytes")]
    pub pk_yk: Vec<u8>,
    /// Path in the cohort tree.
    pub path: MembershipPath,
    /// Cohort root.
    pub root: Poseidon2Digest,
    /// Cohort size.
    pub cohort_size: usize,
}

/// Public context the prover commits to.
#[derive(Debug, Clone)]
pub struct EpochPublic {
    /// 2 or 3.
    pub profile: u8,
    /// Policy bundle.
    pub policy_blake3: [u8; 32],
    /// TUF snapshot root.
    pub tuf_snapshot_root: [u8; 32],
    /// Journal state before the epoch.
    pub j_prev: Poseidon2Digest,
}

/// `nullifier_e`.
pub fn nullifier(id_enclave: &[u8; 32], e: &str) -> [u8; 32] {
    let mut b = id_enclave.to_vec();
    b.extend_from_slice(e.as_bytes());
    digest_bytes(&hash_bytes(DOM_NULL, &b))
}

/// Poseidon2 journal fold.
pub fn journal_fold(j: Poseidon2Digest, lines: &[Vec<u8>]) -> Poseidon2Digest {
    lines.iter().fold(j, |acc, l| {
        compress(DOM_JOURNAL, &acc, &hash_bytes(AUDIT_LINE_DOMAIN, l))
    })
}

/// Evaluate `R_epoch` natively with entering QIF state `used_in` (GAP-24).
#[allow(clippy::too_many_arguments)]
pub fn prove_rollup_at(
    public: &EpochPublic,
    id_enclave: &[u8; 32],
    entity: &str,
    slots: &[SlotWitness],
    journal_lines: &[Vec<u8>],
    tombstone_keys: &TombstoneKeys,
    hw: Option<&HardwareWitness>,
    hw_batch_sigs: Option<Vec<String>>,
    heartbeat: bool,
    used_in: u32,
) -> EnclaveResult<(Vec<u8>, u32)> {
    if slots.is_empty() {
        fail!(EINVAL, "EPOCH_EMPTY");
    }
    if slots.len() > MAX_SLOTS_PER_FRAME {
        fail!(
            E2BIG,
            "EPOCH_SPLIT_REQUIRED",
            "{} slots > {MAX_SLOTS_PER_FRAME} per frame",
            slots.len()
        );
    }
    let s_start = slots[0].seq();
    let s_end = s_start
        .checked_add(slots.len() as u64 - 1)
        .ok_or_else(|| enclave_core::err!(EINVAL, "SLOT_SPAN_OVERFLOW"))?;
    for (i, s) in slots.iter().enumerate() {
        if s.seq() != s_start + i as u64 {
            fail!(
                EACCES,
                "SLOT_GAP",
                "slot {} missing: neither fold nor tombstone",
                s_start + i as u64
            );
        }
    }
    let mut kinds = Vec::with_capacity(slots.len());
    let mut total = 0u64;
    for s in slots {
        match s {
            SlotWitness::Fold {
                seq,
                scrubbed,
                qif_delta_mb,
            } => {
                let text = String::from_utf8_lossy(scrubbed);
                let leaks = scan(&text).into_iter().filter(|x| x.kind.is_c4()).count();
                if leaks != 0 {
                    fail!(
                        EACCES,
                        "UNREDACTED_C4_IN_FOLD",
                        "slot {seq}: {leaks} span(s)"
                    );
                }
                let (_dfa_st, reject) = crate::zk::lasso_dfa::eval_dfa_bytes(0, scrubbed);
                if reject {
                    fail!(
                        EACCES,
                        "UNREDACTED_C4_IN_FOLD",
                        "slot {seq}: native DFA detected unredacted PII in fold"
                    );
                }
                total += *qif_delta_mb as u64;
                kinds.push(SlotKind::Fold {
                    delta_mb: *qif_delta_mb,
                });
            }
            SlotWitness::Tombstone(t) => {
                t.verify(tombstone_keys)?;
                kinds.push(SlotKind::Tombstone);
            }
        }
    }
    // At most 4096 u32 deltas plus one u32 entering state fit in u64.
    // Compare before narrowing: an attacker-controlled total may exceed 2^32.
    let used_out_wide = u64::from(used_in) + total;
    if used_out_wide > u64::from(QIF_CAP_MB) {
        fail!(EACCES, "QIF_BUDGET_EXCEEDED", "{used_out_wide} mb");
    }
    let used_out = used_out_wide as u32; // Proven <= QIF_CAP_MB above.
    let r_fleet = match (public.profile, hw) {
        (3, Some(h)) => {
            if h.cohort_size < MIN_COHORT {
                fail!(EPERM, "COHORT_TOO_SMALL");
            }
            if !verify_membership(&h.root, &leaf(&h.pk_sep, &h.pk_yk), &h.path, h.cohort_size) {
                fail!(EACCES, "HARDWARE_NOT_IN_COHORT");
            }
            digest_bytes(&h.root)
        }
        (3, None) => fail!(EPERM, "L3_REQUIRES_COHORT_MEMBERSHIP"),
        (2, _) => [0u8; 32],
        _ => fail!(EINVAL, "ROLLUP_PROFILE"),
    };
    let j_curr = journal_fold(public.j_prev, journal_lines);
    let nullifier_bytes = nullifier(id_enclave, entity);
    // Legacy transcript placeholder, NOT an authenticated QIF-tree root (F115).
    let qif_root = digest_bytes(&enclave_core::poseidon2::hash_bytes(
        b"MCPMac-QifTree-v1",
        &nullifier_bytes,
    ));
    let cohort_size = if public.profile == 3 {
        hw.map(|h| h.cohort_size as u32).unwrap_or(0)
    } else {
        0
    };
    let stmt = EpochStatement {
        vk_digest: vk_digest(),
        profile: public.profile,
        policy_blake3: public.policy_blake3,
        tuf_snapshot_root: public.tuf_snapshot_root,
        qif_cap_mb: 12_000,
        r_fleet_pk: r_fleet,
        j_prev: digest_bytes(&public.j_prev),
        j_curr: digest_bytes(&j_curr),
        nullifier_e: nullifier_bytes,
        qif_root_prev: qif_root,
        qif_root_curr: qif_root,
        s_start,
        s_end,
        used_in,
        used_out,
        cohort_size,
    };
    let proof = prove_epoch_private(&stmt, &kinds)?;
    let frame = ComplianceRollupProofV1::build(
        &stmt,
        proof,
        hw.map(|h| h.cohort_size as u64),
        heartbeat,
        hw_batch_sigs,
    )?;
    Ok((frame, used_out))
}

/// Evaluate `R_epoch` natively and, if it holds, prove and frame it.
#[allow(clippy::too_many_arguments)]
pub fn prove_rollup(
    public: &EpochPublic,
    id_enclave: &[u8; 32],
    entity: &str,
    slots: &[SlotWitness],
    journal_lines: &[Vec<u8>],
    tombstone_keys: &TombstoneKeys,
    hw: Option<&HardwareWitness>,
    hw_batch_sigs: Option<Vec<String>>,
    heartbeat: bool,
) -> EnclaveResult<Vec<u8>> {
    prove_rollup_at(
        public,
        id_enclave,
        entity,
        slots,
        journal_lines,
        tombstone_keys,
        hw,
        hw_batch_sigs,
        heartbeat,
        0,
    )
    .map(|(frame, _)| frame)
}

/// One frame's worth of witness in a series.
#[derive(Debug, Clone)]
pub struct EpochChunk {
    /// Slots (at most [`MAX_SLOTS_PER_FRAME`]).
    pub slots: Vec<SlotWitness>,
    /// Audit lines folded by this frame.
    pub journal_lines: Vec<Vec<u8>>,
}

/// Prove an epoch longer than one frame as a series: frame `i + 1` starts at
/// `s_end(i) + 1` and its `J_prev` is frame `i`'s `J_curr`; the 24 h QIF cap is
/// enforced over the whole series before any frame is emitted.
#[allow(clippy::too_many_arguments)]
pub fn prove_rollup_series(
    public: &EpochPublic,
    id_enclave: &[u8; 32],
    entity: &str,
    chunks: &[EpochChunk],
    tombstone_keys: &TombstoneKeys,
    hw: Option<&HardwareWitness>,
    hw_batch_sigs: Option<Vec<String>>,
    heartbeat: bool,
) -> EnclaveResult<Vec<Vec<u8>>> {
    let total: u64 = chunks
        .iter()
        .flat_map(|c| c.slots.iter())
        .map(|s| match s {
            SlotWitness::Fold { qif_delta_mb, .. } => *qif_delta_mb as u64,
            SlotWitness::Tombstone(_) => 0,
        })
        .sum();
    if total > 12_000 {
        fail!(EACCES, "QIF_BUDGET_EXCEEDED", "series total {total} mb");
    }
    let mut previous_end: Option<u64> = None;
    let mut p = public.clone();
    let mut out = Vec::with_capacity(chunks.len());
    let mut current_used = 0u32;
    for c in chunks {
        let first = c
            .slots
            .first()
            .map(SlotWitness::seq)
            .ok_or_else(|| enclave_core::err!(EINVAL, "EPOCH_EMPTY"))?;
        if let Some(end) = previous_end {
            if end.checked_add(1) != Some(first) {
                fail!(EACCES, "SLOT_GAP", "series discontinuity at {first}");
            }
        }
        let end = first
            .checked_add(c.slots.len() as u64 - 1)
            .ok_or_else(|| enclave_core::err!(EINVAL, "SLOT_SPAN_OVERFLOW"))?;
        let (frame, next_used) = prove_rollup_at(
            &p,
            id_enclave,
            entity,
            &c.slots,
            &c.journal_lines,
            tombstone_keys,
            hw,
            hw_batch_sigs.clone(),
            heartbeat,
            current_used,
        )?;
        current_used = next_used;
        out.push(frame);
        p.j_prev = journal_fold(p.j_prev, &c.journal_lines);
        previous_end = Some(end);
    }
    Ok(out)
}
