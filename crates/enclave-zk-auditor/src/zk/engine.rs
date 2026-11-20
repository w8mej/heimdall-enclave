//! Prover/verifier of an accounting range relation over Plonky3 `uni-stark`.
//!
//! Only EpochAir is instantiated. Journal/fleet/nullifier/QIF roots are bound
//! to the transcript but not established by the constraints. Successful
//! verification is not proof of journal validity, PII absence, hardware custody
//! or fleet membership. See ASSURANCE.md and the executable proof_scope tests.

use p3_challenger::{CanObserve, DuplexChallenger};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::QuinticTrinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{FriParameters, HidingFriPcs, TwoAdicFriPcs};
use p3_koala_bear::{default_koalabear_poseidon2_16, KoalaBear, Poseidon2KoalaBear};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::{MerkleTreeHidingMmcs, MerkleTreeMmcs};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{prove, verify, Proof, StarkConfig};
use rand10::rngs::StdRng;
use rand10::{RngExt, SeedableRng};
use chacha20::ChaCha20Rng;
use serde::{Deserialize, Serialize};

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};

use super::air::{col, pv, EpochAir, BITS, NUM_BLIND, NUM_PUBLIC, WIDTH};

/// Base field.
pub type Val = KoalaBear;
/// Challenge field `F_{p^5}`.
pub type Challenge = QuinticTrinomialExtensionField<Val>;
type Perm = Poseidon2KoalaBear<16>;
type Hash = PaddingFreeSponge<Perm, 16, 8, 8>;
type Compress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, Hash, Compress, 2, 8>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
/// Fiat-Shamir challenger (Poseidon2 duplex sponge).
pub type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
type Dft = Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
/// Full STARK configuration.
pub type EpochConfig = StarkConfig<Pcs, Challenge, Challenger>;

/// Hiding value MMCS with randomized leaf salts (FS-705 §3.2 / GAP-23 HVZK).
pub type HidingValMmcs = MerkleTreeHidingMmcs<
    <Val as Field>::Packing,
    <Val as Field>::Packing,
    Hash,
    Compress,
    ChaCha20Rng,
    2,
    8,
    4,
>;
/// Hiding challenge MMCS.
pub type HidingChallengeMmcs = ExtensionMmcs<Val, Challenge, HidingValMmcs>;
/// Hiding FRI PCS with randomized codewords.
pub type HidingPcs = HidingFriPcs<Val, Dft, HidingValMmcs, HidingChallengeMmcs, ChaCha20Rng>;
/// Full STARK configuration with HVZK hiding.
pub type HidingEpochConfig = StarkConfig<HidingPcs, Challenge, Challenger>;

/// FRI blow-up (log2) — `ρ = 1/4`.
pub const LOG_BLOWUP: usize = 2;
/// FRI queries (ADR-017, owner decision 2026-11-05).
pub const NUM_QUERIES: usize = 84;
/// Query-phase proof-of-work bits.
pub const POW_BITS: usize = 16;
/// Merkle cap height (shortens every opening path).
pub const MERKLE_CAP_HEIGHT: usize = 4;
/// FRI folding arity (log2).
pub const MAX_LOG_ARITY: usize = 3;
/// Final polynomial length (log2).
pub const LOG_FINAL_POLY_LEN: usize = 2;
/// Transcript domain string (§3.5.3).
pub const DOMAIN: &str = "MCPMac-ComplianceRollup-v1";
/// Versioned hiding accounting transcript; this does not claim full compliance.
pub const HIDING_DOMAIN: &str = "MCPMac-EpochAccounting-Hiding-v2";
/// Maximum proof size on the wire (FS-705 Rev 1.4, GAP-24: 320 KiB to fit single 4,096-slot epochs).
pub const MAX_PROOF_BYTES: usize = 327_680;

/// Public statement `x` of `R_epoch`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochStatement {
    /// Verifier-key digest.
    pub vk_digest: [u8; 32],
    /// Profile (2 or 3).
    pub profile: u8,
    /// Policy bundle.
    pub policy_blake3: [u8; 32],
    /// TUF snapshot root.
    pub tuf_snapshot_root: [u8; 32],
    /// QIF cap (12000).
    pub qif_cap_mb: u32,
    /// Fleet cohort Merkle root.
    pub r_fleet_pk: [u8; 32],
    /// Journal fold before.
    pub j_prev: [u8; 32],
    /// Journal fold after.
    pub j_curr: [u8; 32],
    /// Nullifier.
    pub nullifier_e: [u8; 32],
    /// Prover-supplied QIF field; V1 frame builder uses a nullifier-derived placeholder.
    pub qif_root_prev: [u8; 32],
    /// Prover-supplied QIF field; no authenticated tree update is constrained.
    pub qif_root_curr: [u8; 32],
    /// First slot.
    pub s_start: u64,
    /// Last slot.
    pub s_end: u64,
    /// QIF millibits entering this frame (GAP-24).
    pub used_in: u32,
    /// QIF millibits exiting this frame (GAP-24).
    pub used_out: u32,
    /// Fleet cohort size committed in R_fleet_pk (D-23e).
    pub cohort_size: u32,
}

/// Per-slot witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotKind {
    /// Valid redaction fold charging `delta_mb`.
    Fold {
        /// Millibits charged.
        delta_mb: u32,
    },
    /// Dual-co-signed `AbortedPreEgressTombstone`.
    Tombstone,
}

fn pack(bytes: &[u8]) -> Vec<Val> {
    bytes
        .chunks(3)
        .map(|c| Val::from_u32(enclave_core::poseidon2::pack24(c)))
        .collect()
}

/// The verifier key digest: binds the AIR shape and every FRI parameter.
pub fn vk_digest() -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MCPMac-R_epoch-VK-v1");
    for v in [
        WIDTH,
        BITS,
        LOG_BLOWUP,
        NUM_QUERIES,
        POW_BITS,
        MERKLE_CAP_HEIGHT,
        MAX_LOG_ARITY,
        LOG_FINAL_POLY_LEN,
        5,
        NUM_PUBLIC,
    ] {
        h.update(&(v as u64).to_be_bytes());
    }
    h.update(b"KoalaBear^5:X^5+X^2-1|Poseidon2-16|");
    h.update(super::air::AIR_DOMAIN.as_bytes());
    *h.finalize().as_bytes()
}

/// Independently pinned key identity for the production hiding configuration.
pub fn hiding_vk_digest() -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MCPMac-HidingAccounting-VK-v2");
    h.update(&vk_digest());
    h.update(HIDING_DOMAIN.as_bytes());
    h.update(b"postcard-1.1.3-reject-trailing");
    // Hiding FRI random codewords, salt field elements, minimum trace height,
    // private OS entropy bytes. These are distinct from the legacy PCS.
    for n in [5u64, 4, 256, 64] {
        h.update(&n.to_be_bytes());
    }
    *h.finalize().as_bytes()
}

fn init_challenger(stmt: &EpochStatement, perm: Perm) -> Challenger {
    init_challenger_domain(stmt, perm, DOMAIN)
}

fn init_challenger_domain(stmt: &EpochStatement, perm: Perm, domain: &str) -> Challenger {
    let mut ch = Challenger::new(perm);
    ch.observe_slice(&pack(domain.as_bytes()));
    for part in [
        &stmt.vk_digest[..],
        &[stmt.profile],
        &stmt.policy_blake3,
        &stmt.tuf_snapshot_root,
    ] {
        ch.observe_slice(&pack(part));
    }
    ch.observe(Val::from_u32(stmt.qif_cap_mb));
    ch.observe(Val::from_u32(stmt.used_in));
    ch.observe(Val::from_u32(stmt.used_out));
    for part in [
        &stmt.r_fleet_pk,
        &stmt.j_prev,
        &stmt.j_curr,
        &stmt.nullifier_e,
        &stmt.qif_root_prev,
        &stmt.qif_root_curr,
    ] {
        ch.observe_slice(&pack(part));
    }
    ch.observe(Val::from_u32(stmt.cohort_size));
    for x in [stmt.s_start, stmt.s_end] {
        for i in 0..4 {
            ch.observe(Val::from_u32(((x >> (16 * i)) & 0xffff) as u32));
        }
    }
    ch
}

/// Build the configuration with the transcript pre-absorbing the domain
/// string and **all** public inputs in the normative order.
pub fn config(stmt: &EpochStatement) -> EpochConfig {
    let perm = default_koalabear_poseidon2_16();
    let hash = Hash::new(perm.clone());
    let compress = Compress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, MERKLE_CAP_HEIGHT);
    let fri = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: LOG_FINAL_POLY_LEN,
        max_log_arity: MAX_LOG_ARITY,
        num_queries: NUM_QUERIES,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: POW_BITS,
        mmcs: ChallengeMmcs::new(val_mmcs.clone()),
    };
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri);
    let ch = init_challenger(stmt, perm);
    StarkConfig::new(pcs, ch)
}

/// Build the HVZK hiding configuration (FS-705 §3.2 / GAP-23).
/// Deterministic seed helper for tests/benchmarks only; production proving uses
/// OS CSPRNG entropy via `prove_epoch_private_with_entropy`.
pub fn hiding_config(stmt: &EpochStatement, seed: u64) -> HidingEpochConfig {
    hiding_config_rngs(
        stmt,
        ChaCha20Rng::seed_from_u64(seed), // DevSkim: ignore DS148264 (test/benchmark deterministic helper)
        ChaCha20Rng::seed_from_u64(seed.wrapping_add(0x9e3779b97f4a7c15)), // DevSkim: ignore DS148264 (test/benchmark deterministic helper)
        DOMAIN,
    )
}

fn hiding_config_rngs(
    stmt: &EpochStatement,
    salts: ChaCha20Rng,
    masks: ChaCha20Rng,
    domain: &str,
) -> HidingEpochConfig {
    let perm = default_koalabear_poseidon2_16();
    let hash = Hash::new(perm.clone());
    let compress = Compress::new(perm.clone());
    let val_mmcs = HidingValMmcs::new(hash, compress, MERKLE_CAP_HEIGHT, salts);
    let challenge_mmcs = HidingChallengeMmcs::new(val_mmcs.clone());
    let fri = FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: LOG_FINAL_POLY_LEN,
        max_log_arity: MAX_LOG_ARITY,
        num_queries: NUM_QUERIES,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: POW_BITS,
        mmcs: challenge_mmcs,
    };
    let pcs = HidingPcs::new(Dft::default(), val_mmcs, fri, 5, masks);
    let ch = init_challenger_domain(stmt, perm, domain);
    HidingEpochConfig::new(pcs, ch)
}

/// Prove hiding accounting with fresh, private OS entropy. No seed is returned
/// or placed in the frame. The composed compliance relation remains absent.
pub fn prove_epoch_private(stmt: &EpochStatement, slots: &[SlotKind]) -> EnclaveResult<Vec<u8>> {
    prove_epoch_private_with_entropy(stmt, slots, |bytes| {
        use rand_core::RngCore;
        rand_core::OsRng
            .try_fill_bytes(bytes)
            .map_err(|_| err!(EIO, "PROOF_ENTROPY_UNAVAILABLE"))
    })
}

fn private_statement(stmt: &EpochStatement) -> EnclaveResult<()> {
    validate_accounting_range(stmt)?;
    if stmt.vk_digest != hiding_vk_digest() {
        fail!(EACCES, "VK_DIGEST_MISMATCH");
    }
    if !matches!(stmt.profile, 2 | 3)
        || stmt.s_end < stmt.s_start
        || stmt.s_end - stmt.s_start >= 4096
    {
        fail!(EINVAL, "EPOCH_SPAN");
    }
    Ok(())
}

fn prove_epoch_private_with_entropy(
    stmt: &EpochStatement,
    slots: &[SlotKind],
    entropy: impl FnOnce(&mut [u8]) -> EnclaveResult<()>,
) -> EnclaveResult<Vec<u8>> {
    private_statement(stmt)?;
    if slots.len() != (stmt.s_end - stmt.s_start + 1) as usize {
        fail!(EINVAL, "EPOCH_SPAN");
    }
    let mut seed = enclave_core::secret::SecretBytes::zeroed(64);
    entropy(seed.expose_mut())?;
    let config = hiding_config_rngs(
        stmt,
        ChaCha20Rng::from_seed(seed.expose()[..32].try_into().unwrap()),
        ChaCha20Rng::from_seed(seed.expose()[32..].try_into().unwrap()),
        HIDING_DOMAIN,
    );
    seed.wipe();
    let t = trace_padded(slots, stmt.qif_cap_mb, stmt.used_in, 256)?;
    let proof = prove(&config, &EpochAir, t, &make_public_values(stmt))
        .map_err(|e| err!(EIO, "STARK_PROVE", "{e:?}"))?;
    let out = postcard::to_allocvec(&proof).map_err(|e| err!(EIO, "PROOF_ENCODE", "{e}"))?;
    if out.len() > MAX_PROOF_BYTES {
        fail!(E2BIG, "PROOF_TOO_LARGE", "{} bytes", out.len());
    }
    Ok(out)
}

/// Verify using public parameters only. The verifier's deterministic RNGs are
/// unused by verification; no prover randomness is required or transmitted.
pub fn verify_epoch_private(stmt: &EpochStatement, bytes: &[u8]) -> EnclaveResult<()> {
    private_statement(stmt)?;
    if bytes.len() > MAX_PROOF_BYTES {
        fail!(E2BIG, "PROOF_TOO_LARGE");
    }
    let (proof, trailing): (Proof<HidingEpochConfig>, _) =
        postcard::take_from_bytes(bytes).map_err(|e| err!(EINVAL, "PROOF_DECODE", "{e}"))?;
    if !trailing.is_empty() {
        fail!(EINVAL, "PROOF_DECODE");
    }
    let config = hiding_config_rngs(
        stmt,
        ChaCha20Rng::seed_from_u64(0),
        ChaCha20Rng::seed_from_u64(0),
        HIDING_DOMAIN,
    );
    verify(&config, &EpochAir, &proof, &make_public_values(stmt))
        .map_err(|e| err!(EACCES, "STARK_VERIFY_FAILED", "{e:?}"))
}

/// Convert statement into the normative 57-element public values array (GAP-23 / GAP-24).
pub fn make_public_values(stmt: &EpochStatement) -> [Val; NUM_PUBLIC] {
    let mut pis = [Val::ZERO; NUM_PUBLIC];
    pis[pv::SPAN] = Val::from_u64(stmt.s_end - stmt.s_start);
    pis[pv::CAP] = Val::from_u32(stmt.qif_cap_mb);
    pis[pv::USED_IN] = Val::from_u32(stmt.used_in);
    pis[pv::USED_OUT] = Val::from_u32(stmt.used_out);
    let j_in_digest = enclave_core::poseidon2::Poseidon2Digest::from_bytes(&stmt.j_prev);
    for i in 0..8 {
        pis[pv::J_IN + i] = Val::from_u32(j_in_digest.0[i]);
    }
    let j_out_digest = enclave_core::poseidon2::Poseidon2Digest::from_bytes(&stmt.j_curr);
    for i in 0..8 {
        pis[pv::J_OUT + i] = Val::from_u32(j_out_digest.0[i]);
    }
    let nullifier_digest = enclave_core::poseidon2::Poseidon2Digest::from_bytes(&stmt.nullifier_e);
    for i in 0..8 {
        pis[pv::NULLIFIER_E + i] = Val::from_u32(nullifier_digest.0[i]);
    }
    let r_fleet_digest = enclave_core::poseidon2::Poseidon2Digest::from_bytes(&stmt.r_fleet_pk);
    for i in 0..8 {
        pis[pv::R_FLEET_PK + i] = Val::from_u32(r_fleet_digest.0[i]);
    }
    let qif_prev_digest = enclave_core::poseidon2::Poseidon2Digest::from_bytes(&stmt.qif_root_prev);
    for i in 0..8 {
        pis[pv::QIF_ROOT_PREV + i] = Val::from_u32(qif_prev_digest.0[i]);
    }
    let qif_curr_digest = enclave_core::poseidon2::Poseidon2Digest::from_bytes(&stmt.qif_root_curr);
    for i in 0..8 {
        pis[pv::QIF_ROOT_CURR + i] = Val::from_u32(qif_curr_digest.0[i]);
    }
    pis[pv::S_START_LOW] = Val::from_u32((stmt.s_start & 0xffffffff) as u32);
    pis[pv::S_START_HIGH] = Val::from_u32(((stmt.s_start >> 32) & 0xffffffff) as u32);
    pis[pv::S_END_LOW] = Val::from_u32((stmt.s_end & 0xffffffff) as u32);
    pis[pv::S_END_HIGH] = Val::from_u32(((stmt.s_end >> 32) & 0xffffffff) as u32);
    pis[pv::COHORT_SIZE] = Val::from_u32(stmt.cohort_size);
    pis
}

/// Generate the trace padded to a power of two, minimum `min_rows` (GAP-23 HVZK).
pub fn trace_padded(
    slots: &[SlotKind],
    cap: u32,
    used_in: u32,
    min_rows: usize,
) -> EnclaveResult<RowMajorMatrix<Val>> {
    if slots.is_empty() {
        fail!(EINVAL, "EPOCH_EMPTY");
    }
    if cap >= 1 << BITS {
        fail!(EINVAL, "QIF_CAP_RANGE");
    }
    if used_in > cap {
        fail!(
            EACCES,
            "QIF_BUDGET_EXCEEDED",
            "entering total {used_in} > {cap} mb"
        );
    }
    let rows = slots.len().next_power_of_two().max(min_rows);
    let mut v = vec![Val::ZERO; rows * WIDTH];
    let mut used: u64 = used_in as u64;
    let mut rng = StdRng::seed_from_u64(0x4d43504d61635a4b);
    for r in 0..rows {
        let row = &mut v[r * WIDTH..(r + 1) * WIDTH];
        let (active, fold, tomb, delta) = match slots.get(r) {
            Some(SlotKind::Fold { delta_mb }) => (1, 1, 0, *delta_mb),
            Some(SlotKind::Tombstone) => (1, 0, 1, 0),
            None => (0, 0, 0, 0),
        };
        if delta >= 1 << BITS {
            fail!(E2BIG, "QIF_DELTA_RANGE");
        }
        used += delta as u64;
        if used > cap as u64 {
            fail!(
                EACCES,
                "QIF_BUDGET_EXCEEDED",
                "epoch total {used} > {cap} mb: no valid proof exists"
            );
        }
        let seq = if active == 1 {
            r as u32
        } else {
            (slots.len() - 1) as u32
        };
        row[col::ACTIVE] = Val::from_u32(active);
        row[col::SEQ] = Val::from_u32(seq);
        row[col::IS_FOLD] = Val::from_u32(fold);
        row[col::IS_TOMB] = Val::from_u32(tomb);
        row[col::DELTA] = Val::from_u32(delta);
        row[col::USED] = Val::from_u64(used);
        let slack = cap as u64 - used;
        for i in 0..BITS {
            row[col::SLACK + i] = Val::from_u64((slack >> i) & 1);
            row[col::DBITS + i] = Val::from_u32((delta >> i) & 1);
            row[col::UBITS + i] = Val::from_u64((used >> i) & 1);
        }
        for b in 0..NUM_BLIND {
            row[col::BLIND + b] = Val::from_u32(rng.random::<u32>());
        }
    }
    Ok(RowMajorMatrix::new(v, WIDTH))
}

/// Generate the trace (padded to a power of two, minimum 8 rows).
pub fn trace(slots: &[SlotKind], cap: u32, used_in: u32) -> EnclaveResult<RowMajorMatrix<Val>> {
    trace_padded(slots, cap, used_in, 8)
}

/// Prove the accounting relation for a prover-supplied slot sequence.
pub fn prove_epoch(stmt: &EpochStatement, slots: &[SlotKind]) -> EnclaveResult<Vec<u8>> {
    validate_accounting_range(stmt)?;
    if stmt.s_end < stmt.s_start
        || stmt.s_end - stmt.s_start >= 1 << 20
        || (stmt.s_end - stmt.s_start + 1) as usize != slots.len()
        || slots.len() > 1 << 20
    {
        fail!(EINVAL, "EPOCH_SPAN");
    }
    if stmt.vk_digest != vk_digest() {
        fail!(EACCES, "VK_DIGEST_MISMATCH");
    }
    let t = trace(slots, stmt.qif_cap_mb, stmt.used_in)?;
    let pis = make_public_values(stmt);
    let proof =
        prove(&config(stmt), &EpochAir, t, &pis).map_err(|e| err!(EIO, "STARK_PROVE", "{e:?}"))?;
    let mut out = Vec::new();
    ciborium::into_writer(&proof, &mut out).map_err(|e| err!(EIO, "PROOF_ENCODE", "{e}"))?;
    Ok(out)
}

/// Prove the same accounting relation using the hiding PCS configuration.
/// This does not add the missing journal, redaction or membership relations;
/// a seeded hiding configuration is not by itself a production privacy claim.
pub fn prove_epoch_hiding(
    stmt: &EpochStatement,
    slots: &[SlotKind],
    seed: u64,
) -> EnclaveResult<Vec<u8>> {
    validate_accounting_range(stmt)?;
    if stmt.s_end < stmt.s_start
        || stmt.s_end - stmt.s_start >= 1 << 20
        || (stmt.s_end - stmt.s_start + 1) as usize != slots.len()
        || slots.len() > 1 << 20
    {
        fail!(EINVAL, "EPOCH_SPAN");
    }
    if stmt.vk_digest != vk_digest() {
        fail!(EACCES, "VK_DIGEST_MISMATCH");
    }
    // Hiding PCS requires trace height >= 256 to cover the hiding budget:
    // N >= 2 * (num_queries (84) + Challenge::DIMENSION (5) * 2) = 188 <= 256.
    let t = trace_padded(slots, stmt.qif_cap_mb, stmt.used_in, 256)?;
    let pis = make_public_values(stmt);
    let proof = prove(&hiding_config(stmt, seed), &EpochAir, t, &pis)
        .map_err(|e| err!(EIO, "STARK_PROVE", "{e:?}"))?;
    let mut out = Vec::new();
    ciborium::into_writer(&proof, &mut out).map_err(|e| err!(EIO, "PROOF_ENCODE", "{e}"))?;
    Ok(out)
}

/// Verify an HVZK proof against the statement.
pub fn verify_epoch_hiding(
    stmt: &EpochStatement,
    proof_bytes: &[u8],
    seed: u64,
) -> EnclaveResult<()> {
    validate_accounting_range(stmt)?;
    if stmt.vk_digest != vk_digest() {
        fail!(EACCES, "VK_DIGEST_MISMATCH");
    }
    if stmt.s_end < stmt.s_start || stmt.s_end - stmt.s_start >= 1 << 20 {
        fail!(EINVAL, "EPOCH_SPAN");
    }
    let mut remaining = proof_bytes;
    let proof: Proof<HidingEpochConfig> =
        ciborium::from_reader(&mut remaining).map_err(|e| err!(EINVAL, "PROOF_DECODE", "{e}"))?;
    if !remaining.is_empty() {
        fail!(EINVAL, "PROOF_DECODE");
    }
    let pis = make_public_values(stmt);
    verify(&hiding_config(stmt, seed), &EpochAir, &proof, &pis)
        .map_err(|e| err!(EACCES, "STARK_VERIFY_FAILED", "{e:?}"))?;
    Ok(())
}

/// Verify an accounting proof against a prover-supplied statement.
/// Transcript binding prevents reattachment; it does not establish the truth
/// of the journal, fleet, nullifier or QIF-tree fields.
pub fn verify_epoch(stmt: &EpochStatement, proof_bytes: &[u8]) -> EnclaveResult<()> {
    validate_accounting_range(stmt)?;
    if stmt.vk_digest != vk_digest() {
        fail!(EACCES, "VK_DIGEST_MISMATCH");
    }
    if stmt.s_end < stmt.s_start || stmt.s_end - stmt.s_start >= 1 << 20 {
        fail!(EINVAL, "EPOCH_SPAN");
    }
    if proof_bytes.len() > 4 * MAX_PROOF_BYTES {
        fail!(E2BIG, "PROOF_TOO_LARGE");
    }
    let mut remaining = proof_bytes;
    let proof: Proof<EpochConfig> =
        ciborium::from_reader(&mut remaining).map_err(|e| err!(EINVAL, "PROOF_DECODE", "{e}"))?;
    if !remaining.is_empty() {
        fail!(EINVAL, "PROOF_DECODE");
    }
    let pis = make_public_values(stmt);
    verify(&config(stmt), &EpochAir, &proof, &pis)
        .map_err(|e| err!(EACCES, "STARK_VERIFY_FAILED", "{e:?}"))
}

/// Public integers must have their intended small, canonical representation.
/// This is also required for lifting the AIR's field additions to integer sums.
fn validate_accounting_range(stmt: &EpochStatement) -> EnclaveResult<()> {
    if stmt.qif_cap_mb >= 1 << BITS
        || stmt.used_in > stmt.qif_cap_mb
        || stmt.used_out > stmt.qif_cap_mb
    {
        fail!(EACCES, "QIF_PUBLIC_RANGE");
    }
    Ok(())
}

#[cfg(test)]
mod private_tests {
    use super::*;
    #[test]
    fn phase5_private_rng_erases_state_and_buffer_on_drop() {
        // This bound fails compilation if the pinned implementation loses the
        // feature that erases both its cipher state and buffered output.
        fn erases<T: zeroize::ZeroizeOnDrop>() {}
        erases::<ChaCha20Rng>();
        // RFC 8439 zero-key/zero-nonce ChaCha20 first block, independent of rand's
        // unspecified StdRng algorithm. No private seed is used in this check.
        let mut rng = ChaCha20Rng::from_seed([0; 32]);
        let mut out = [0u8; 64];
        rand10::Rng::fill_bytes(&mut rng, &mut out);
        assert_eq!(hex::encode(out), "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586");
    }
    fn statement() -> EpochStatement {
        EpochStatement {
            vk_digest: hiding_vk_digest(),
            profile: 2,
            policy_blake3: [1; 32],
            tuf_snapshot_root: [2; 32],
            qif_cap_mb: 12_000,
            r_fleet_pk: [0; 32],
            j_prev: [3; 32],
            j_curr: [4; 32],
            nullifier_e: [5; 32],
            qif_root_prev: [6; 32],
            qif_root_curr: [6; 32],
            s_start: 1,
            s_end: 1,
            used_in: 0,
            used_out: 3,
            cohort_size: 0,
        }
    }
    #[test]
    fn phase5_private_entropy_failure_and_span_bounds_fail_before_proving() {
        let mut stmt = statement();
        let slots = [SlotKind::Fold { delta_mb: 3 }];
        let error = prove_epoch_private_with_entropy(&stmt, &slots, |_| {
            Err(err!(EIO, "PROOF_ENTROPY_UNAVAILABLE"))
        })
        .unwrap_err();
        assert!(error.is("PROOF_ENTROPY_UNAVAILABLE"));
        for end in [0, 4097, u64::MAX] {
            stmt.s_end = end;
            assert!(prove_epoch_private_with_entropy(&stmt, &slots, |_| panic!(
                "invalid span consumed entropy"
            ))
            .is_err());
        }
        stmt = statement();
        stmt.vk_digest = vk_digest();
        assert!(prove_epoch_private_with_entropy(&stmt, &slots, |_| panic!(
            "wrong key consumed entropy"
        ))
        .is_err());
        assert!(
            verify_epoch_private(&statement(), &vec![0; MAX_PROOF_BYTES + 1])
                .unwrap_err()
                .is("PROOF_TOO_LARGE")
        );
    }
}
