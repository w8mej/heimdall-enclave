//! `ComplianceRollupProofV1` (FS-705 §7.3, `schemas/compliance-rollup-proof-v1.schema.json`).
//!
//! Binary CBOR on the wire; the complete frame is at most 327,680 bytes; in `L3` frames are
//! padded to exactly **327,680** bytes (`320 KiB`), require `cohort_size >= 32` and a
//! `heartbeat` flag, and must not carry `hardware_batch_anchor_sigs`; in `L2`
//! those signatures are required (attribution is expected, supporting hybrid
//! `Ed25519 + NIST FIPS 204 ML-DSA-65` dual-signatures per `FS-707`).

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::cohort::digest_bytes;
use crate::zk::engine::{
    hiding_vk_digest, verify_epoch, verify_epoch_private, EpochStatement, LOG_BLOWUP,
    MAX_PROOF_BYTES, NUM_QUERIES, POW_BITS,
};

/// Complete compliance frame ceiling, including CBOR headers and L2 anchors
/// (FS-705 §3.5.1, YKD-10). Outer OHTTP/TLS overhead is separate.
pub const MAX_FRAME_BYTES: usize = 327_680;
/// Exact `L3` frame size, including zero padding.
pub const L3_FRAME_BYTES: usize = MAX_FRAME_BYTES;
/// Standard ledger authority inside the OHTTP-protected BHTTP request.
pub const LEDGER_AUTHORITY: &str = "ledger.corporate.internal";
/// Standard ledger path shared by producer, relay and receiver.
pub const LEDGER_PATH: &str = "/v1/rollup";
/// Required QIF cap.
pub const QIF_CAP_MB: u32 = 12_000;

/// Verifier-selected trust supplied independently of the received frame.
/// L3 pins the declared fleet root/count; the missing membership relation (F78)
/// means this still cannot establish membership or anonymity of the sender.
#[derive(Debug, Clone, Copy)]
pub enum RollupTrust<'a> {
    /// Expected issuer key obtained through authenticated configuration.
    L2Anchor(&'a enclave_crypto::pqc::HybridVerifyingKey),
    /// Expected enrollment root and unique-leaf count from fleet administration.
    L3Cohort {
        /// Independently authenticated fleet enrollment commitment.
        root: &'a [u8; 32],
        /// Count authenticated by the fleet authority, not the sender.
        size: u32,
    },
}

/// Public inputs block (hex view).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_snake_case)]
#[serde(deny_unknown_fields)]
pub struct PublicInputs {
    /// vk digest.
    pub vk_digest: String,
    /// Policy.
    pub policy_blake3: String,
    /// TUF snapshot root.
    pub tuf_snapshot_root: String,
    /// QIF cap.
    pub qif_cap_mb: u32,
    /// Fleet root.
    pub R_fleet_pk: String,
    /// Journal before.
    pub J_prev: String,
    /// Journal after.
    pub J_curr: String,
    /// Nullifier.
    pub nullifier_e: String,
    /// Redaction check status (GAP-10: "native" until in-circuit redaction exists).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub redaction_checked: Option<String>,
    /// QIF millibits used entering this frame (GAP-24).
    #[serde(default)]
    pub used_in: u32,
    /// QIF millibits used exiting this frame (GAP-24).
    #[serde(default)]
    pub used_out: u32,
}

/// FRI parameters block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FriBlock {
    /// Blow-up factor.
    pub blowup: u32,
    /// Queries.
    pub queries: u32,
    /// PoW bits.
    pub pow_bits: u32,
}

/// The CBOR frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComplianceRollupProofV1 {
    /// 1: legacy non-hiding accounting; 2: hiding accounting with a distinct key.
    pub v: u8,
    /// `cbor`.
    pub encoding: String,
    /// 2 or 3.
    pub profile: u8,
    /// Public inputs.
    pub public_inputs: PublicInputs,
    /// `KoalaBear^5`.
    pub field: String,
    /// FRI.
    pub fri: FriBlock,
    /// Proof length.
    pub proof_bytes_len: u64,
    /// Total frame size after padding.
    pub padded_frame_bytes: u64,
    /// Cohort size (L3).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cohort_size: Option<u64>,
    /// Heartbeat (L3).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub heartbeat: Option<bool>,
    /// L2 hardware batch anchor signatures (hex).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub hardware_batch_anchor_sigs: Option<Vec<String>>,
    /// First slot.
    pub s_start: u64,
    /// Last slot.
    pub s_end: u64,
    /// STARK proof bytes.
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
    /// Constant-size padding.
    #[serde(with = "serde_bytes")]
    pub padding: Vec<u8>,
}

fn hx(b: &[u8; 32]) -> String {
    hex::encode(b)
}

fn unhex32(s: &str) -> EnclaveResult<[u8; 32]> {
    let v = hex::decode(s).map_err(|_| err!(EINVAL, "ROLLUP_HEX"))?;
    v.try_into().map_err(|_| err!(EINVAL, "ROLLUP_HEX"))
}

impl ComplianceRollupProofV1 {
    /// Assemble a frame (padding applied for `L3`).
    pub fn build(
        stmt: &EpochStatement,
        proof: Vec<u8>,
        cohort_size: Option<u64>,
        heartbeat: bool,
        hw_sigs: Option<Vec<String>>,
    ) -> EnclaveResult<Vec<u8>> {
        if proof.len() > MAX_PROOF_BYTES {
            fail!(
                E2BIG,
                "PROOF_TOO_LARGE",
                "{} > {MAX_PROOF_BYTES}: split the epoch",
                proof.len()
            );
        }
        let mut f = Self {
            v: if stmt.vk_digest == hiding_vk_digest() {
                2
            } else {
                1
            },
            encoding: "cbor".into(),
            profile: stmt.profile,
            public_inputs: PublicInputs {
                vk_digest: hx(&stmt.vk_digest),
                policy_blake3: hx(&stmt.policy_blake3),
                tuf_snapshot_root: hx(&stmt.tuf_snapshot_root),
                qif_cap_mb: stmt.qif_cap_mb,
                R_fleet_pk: hx(&stmt.r_fleet_pk),
                J_prev: hx(&stmt.j_prev),
                J_curr: hx(&stmt.j_curr),
                nullifier_e: hx(&stmt.nullifier_e),
                redaction_checked: Some("native".into()),
                used_in: stmt.used_in,
                used_out: stmt.used_out,
            },
            field: "KoalaBear^5".into(),
            fri: FriBlock {
                blowup: 1 << LOG_BLOWUP,
                queries: NUM_QUERIES as u32,
                pow_bits: POW_BITS as u32,
            },
            proof_bytes_len: proof.len() as u64,
            padded_frame_bytes: 0,
            cohort_size: if stmt.profile == 3 { cohort_size } else { None },
            heartbeat: (stmt.profile == 3).then_some(heartbeat),
            hardware_batch_anchor_sigs: if stmt.profile == 2 { hw_sigs } else { None },
            s_start: stmt.s_start,
            s_end: stmt.s_end,
            proof,
            padding: vec![],
        };
        if stmt.profile == 3 {
            f.padded_frame_bytes = L3_FRAME_BYTES as u64;
            // Grow padding until the encoding is exactly 320 KiB.
            for _ in 0..8 {
                let n = f.encode()?.len();
                if n == L3_FRAME_BYTES {
                    break;
                }
                if n > L3_FRAME_BYTES && f.padding.is_empty() {
                    fail!(E2BIG, "FRAME_OVERFLOW");
                }
                let target =
                    (f.padding.len() as i64 + L3_FRAME_BYTES as i64 - n as i64).max(0) as usize;
                f.padding = vec![0u8; target];
            }
        } else {
            // The length field is part of the encoding: iterate to a fixed point.
            for _ in 0..4 {
                let n = f.encode()?.len() as u64;
                if n == f.padded_frame_bytes {
                    break;
                }
                f.padded_frame_bytes = n;
            }
        }
        let out = f.encode()?;
        f.validate_frame(out.len())?;
        Ok(out)
    }

    fn encode(&self) -> EnclaveResult<Vec<u8>> {
        let mut o = Vec::new();
        ciborium::into_writer(self, &mut o).map_err(|e| err!(EINVAL, "ROLLUP_ENCODE", "{e}"))?;
        Ok(o)
    }

    /// Decode and validate a wire frame.
    pub fn decode(b: &[u8]) -> EnclaveResult<Self> {
        if b.len() > MAX_FRAME_BYTES {
            fail!(E2BIG, "ROLLUP_FRAME_TOO_LARGE");
        }
        let mut remaining = b;
        let f: Self = ciborium::from_reader(&mut remaining)
            .map_err(|e| err!(EINVAL, "ROLLUP_DECODE", "{e}"))?;
        if !remaining.is_empty() {
            fail!(EINVAL, "ROLLUP_TRAILING_BYTES");
        }
        f.validate_frame(b.len())?;
        Ok(f)
    }

    /// Schema + profile rules.
    pub fn validate_frame(&self, wire_len: usize) -> EnclaveResult<()> {
        if wire_len > MAX_FRAME_BYTES {
            fail!(E2BIG, "ROLLUP_FRAME_TOO_LARGE");
        }
        if !matches!(self.v, 1 | 2) || self.encoding != "cbor" || self.field != "KoalaBear^5" {
            fail!(EINVAL, "ROLLUP_HEADER");
        }
        if self.public_inputs.qif_cap_mb != QIF_CAP_MB {
            fail!(EINVAL, "ROLLUP_QIF_CAP");
        }
        if self.fri
            != (FriBlock {
                blowup: 4,
                queries: 84,
                pow_bits: 16,
            })
        {
            fail!(
                EACCES,
                "ROLLUP_FRI_PARAMS",
                "84 queries + 16-bit PoW at rho = 1/4 are normative"
            );
        }
        if self.proof_bytes_len == 0
            || self.proof_bytes_len > MAX_PROOF_BYTES as u64
            || self.proof_bytes_len != self.proof.len() as u64
        {
            fail!(E2BIG, "ROLLUP_PROOF_LEN");
        }
        if self.padded_frame_bytes != wire_len as u64 {
            fail!(EINVAL, "ROLLUP_PADDED_LEN");
        }
        // Padding is transport cover, never an unauthenticated payload channel.
        if self.padding.iter().any(|byte| *byte != 0) {
            fail!(EINVAL, "ROLLUP_NONZERO_PADDING");
        }
        match self.profile {
            3 => {
                if wire_len != L3_FRAME_BYTES {
                    fail!(EACCES, "L3_FRAME_NOT_320KIB");
                }
                if self
                    .cohort_size
                    .is_none_or(|c| c < 32 || c > crate::cohort::MAX_COHORT as u64)
                    || self.heartbeat.is_none()
                {
                    fail!(EACCES, "L3_COHORT_OR_HEARTBEAT");
                }
                if self.hardware_batch_anchor_sigs.is_some() {
                    fail!(
                        EACCES,
                        "L3_HARDWARE_SIGS_ON_WIRE",
                        "L3 frames carry zero hardware identifiers"
                    );
                }
            }
            2 => {
                if self
                    .hardware_batch_anchor_sigs
                    .as_ref()
                    .is_none_or(Vec::is_empty)
                {
                    fail!(EACCES, "L2_HARDWARE_SIGS_REQUIRED");
                }
            }
            _ => fail!(EINVAL, "ROLLUP_PROFILE"),
        }
        Ok(())
    }

    /// Validate the JSON view (`schemas/compliance-rollup-proof-v1.schema.json`
    /// examples) under the same profile rules as the CBOR frame.
    pub fn validate_json_view(v: &Value) -> EnclaveResult<()> {
        let mut o = v.clone();
        let len = v
            .get("proof_bytes_len")
            .and_then(Value::as_u64)
            .ok_or_else(|| err!(EINVAL, "ROLLUP_PROOF_LEN"))?;
        if len > MAX_PROOF_BYTES as u64 {
            fail!(E2BIG, "ROLLUP_PROOF_LEN");
        }
        // `field` / `fri` are optional in the JSON view; when present they are consts.
        if o.get("field").is_none() {
            o["field"] = json!("KoalaBear^5");
        }
        if o.get("fri").is_none() {
            o["fri"] =
                json!({"blowup": 1 << LOG_BLOWUP, "queries": NUM_QUERIES, "pow_bits": POW_BITS});
        }
        o["proof"] = json!(vec![0u8; len as usize]);
        o["padding"] = json!(Vec::<u8>::new());
        o["s_start"] = json!(0);
        o["s_end"] = json!(0);
        let f: Self =
            serde_json::from_value(o).map_err(|e| err!(EINVAL, "ROLLUP_SCHEMA", "{e}"))?;
        let wire =
            usize::try_from(f.padded_frame_bytes).map_err(|_| err!(EINVAL, "ROLLUP_PADDED_LEN"))?;
        f.validate_frame(wire)?;
        // This view omits proof and padding bytes. Check that the claimed total
        // can at least hold the declared proof and actual encoded headers and
        // anchors. Only decode() of the actual wire can establish final size.
        if f.encode()?.len() > wire {
            fail!(E2BIG, "ROLLUP_JSON_OVERHEAD");
        }
        Ok(())
    }

    /// The statement the proof must verify against.
    pub fn statement(&self) -> EnclaveResult<EpochStatement> {
        let p = &self.public_inputs;
        let nullifier_bytes = unhex32(&p.nullifier_e)?;
        // Legacy transcript placeholder, NOT an authenticated QIF-tree root (F115).
        let qif_root = digest_bytes(&enclave_core::poseidon2::hash_bytes(
            b"depot-QifTree-v1",
            &nullifier_bytes,
        ));
        let cohort_size = if self.profile == 3 {
            self.cohort_size.unwrap_or(0) as u32
        } else {
            0
        };
        Ok(EpochStatement {
            vk_digest: unhex32(&p.vk_digest)?,
            profile: self.profile,
            policy_blake3: unhex32(&p.policy_blake3)?,
            tuf_snapshot_root: unhex32(&p.tuf_snapshot_root)?,
            qif_cap_mb: p.qif_cap_mb,
            r_fleet_pk: unhex32(&p.R_fleet_pk)?,
            j_prev: unhex32(&p.J_prev)?,
            j_curr: unhex32(&p.J_curr)?,
            nullifier_e: nullifier_bytes,
            qif_root_prev: qif_root,
            qif_root_curr: qif_root,
            s_start: self.s_start,
            s_end: self.s_end,
            used_in: p.used_in,
            used_out: p.used_out,
            cohort_size,
        })
    }

    /// Accounting verification only: frame rules, pinned `vk_digest`, STARK.
    /// Does not authenticate an issuer, validate anchor signatures, establish
    /// fleet membership, or prove compliance. Use verify_with_trust for external
    /// anchor/root checks; F78 still limits the resulting relation.
    pub fn verify(b: &[u8], pinned_vk_digests: &[[u8; 32]]) -> EnclaveResult<Self> {
        let f = Self::decode(b)?;
        let st = f.statement()?;
        if !pinned_vk_digests.contains(&st.vk_digest) {
            fail!(EACCES, "VK_NOT_IN_TUF_SNAPSHOT");
        }
        match f.v {
            1 => verify_epoch(&st, &f.proof)?,
            2 => verify_epoch_private(&st, &f.proof)?,
            _ => fail!(EINVAL, "ROLLUP_HEADER"),
        }
        Ok(f)
    }

    /// Verify accounting and apply independently selected issuer/fleet trust.
    /// Frame-supplied keys or roots must never be used to construct this policy.
    pub fn verify_with_trust(
        b: &[u8],
        pinned_vk_digests: &[[u8; 32]],
        trust: RollupTrust<'_>,
    ) -> EnclaveResult<Self> {
        let f = Self::verify(b, pinned_vk_digests)?;
        match (f.profile, trust) {
            (2, RollupTrust::L2Anchor(key)) => f.verify_l2_hybrid_anchor(key)?,
            (3, RollupTrust::L3Cohort { root, size }) => {
                if !(crate::cohort::MIN_COHORT as u32..=crate::cohort::MAX_COHORT as u32)
                    .contains(&size)
                    || f.cohort_size != Some(u64::from(size))
                    || unhex32(&f.public_inputs.R_fleet_pk)? != *root
                {
                    fail!(EACCES, "L3_COHORT_TRUST_MISMATCH");
                }
            }
            _ => fail!(EACCES, "ROLLUP_TRUST_PROFILE_MISMATCH"),
        }
        Ok(f)
    }

    /// Ledger-side multi-frame verification (GAP-24):
    /// Verifies each frame's STARK proof and enforces the chain invariants across frames:
    /// 1. Sequence continuity: `s_start(i) == s_end(i - 1) + 1`.
    /// 2. QIF state chaining: `used_out(i - 1) == used_in(i)`.
    /// 3. Initial used: `used_in(0) == 0`.
    /// 4. Series QIF cap: `used_out(last) <= qif_cap_mb` (12,000).
    /// 5. Journal continuity: `J_curr(i - 1) == J_prev(i)` (no gap or reorder in J).
    /// 6. Consistency of entity / profile / policy across all frames.
    pub fn verify_series(
        frames: &[impl AsRef<[u8]>],
        pinned_vk_digests: &[[u8; 32]],
    ) -> EnclaveResult<Vec<Self>> {
        Self::verify_series_impl(frames, pinned_vk_digests, None)
    }

    /// Apply independently selected authority to every frame before accepting
    /// the series; all existing accounting/sequence/journal checks remain.
    pub fn verify_series_with_trust(
        frames: &[impl AsRef<[u8]>],
        pinned_vk_digests: &[[u8; 32]],
        trust: RollupTrust<'_>,
    ) -> EnclaveResult<Vec<Self>> {
        Self::verify_series_impl(frames, pinned_vk_digests, Some(trust))
    }
    fn verify_series_impl(
        frames: &[impl AsRef<[u8]>],
        pinned_vk_digests: &[[u8; 32]],
        trust: Option<RollupTrust<'_>>,
    ) -> EnclaveResult<Vec<Self>> {
        if frames.is_empty() {
            fail!(EINVAL, "SERIES_EMPTY");
        }
        let mut decoded = Vec::with_capacity(frames.len());
        for (i, f_bytes) in frames.iter().enumerate() {
            let f = match trust {
                Some(trust) => Self::verify_with_trust(f_bytes.as_ref(), pinned_vk_digests, trust),
                None => Self::verify(f_bytes.as_ref(), pinned_vk_digests),
            }
            .map_err(|e| err!(EACCES, "SERIES_FRAME_INVALID", "frame {i}: {e}"))?;
            decoded.push(f);
        }

        // Invariant: frame 0 must start with used_in == 0
        if decoded[0].public_inputs.used_in != 0 {
            fail!(
                EACCES,
                "QIF_INITIAL_NONZERO",
                "frame 0 used_in must be 0, got {}",
                decoded[0].public_inputs.used_in
            );
        }

        for i in 1..decoded.len() {
            let prev = &decoded[i - 1];
            let curr = &decoded[i];

            // Sequence continuity
            if prev.s_end.checked_add(1) != Some(curr.s_start) {
                fail!(
                    EACCES,
                    "SLOT_GAP",
                    "frame {i} starts at {} but previous ended at {}",
                    curr.s_start,
                    prev.s_end
                );
            }

            // QIF chain: used_out(i-1) == used_in(i)
            if prev.public_inputs.used_out != curr.public_inputs.used_in {
                fail!(
                    EACCES,
                    "QIF_CHAIN_BREAK",
                    "frame {i} used_in ({}) != frame {} used_out ({})",
                    curr.public_inputs.used_in,
                    i - 1,
                    prev.public_inputs.used_out
                );
            }

            // Journal continuity: J_curr(i-1) == J_prev(i)
            if prev.public_inputs.J_curr != curr.public_inputs.J_prev {
                fail!(
                    EACCES,
                    "JOURNAL_CHAIN_BREAK",
                    "frame {i} J_prev does not match frame {} J_curr",
                    i - 1
                );
            }

            // Consistency across series
            if curr.profile != prev.profile {
                fail!(EACCES, "SERIES_PROFILE_MISMATCH");
            }
            if curr.public_inputs.policy_blake3 != prev.public_inputs.policy_blake3 {
                fail!(EACCES, "SERIES_POLICY_MISMATCH");
            }
            if curr.public_inputs.tuf_snapshot_root != prev.public_inputs.tuf_snapshot_root {
                fail!(EACCES, "SERIES_TUF_MISMATCH");
            }
            if curr.public_inputs.nullifier_e != prev.public_inputs.nullifier_e {
                fail!(EACCES, "SERIES_NULLIFIER_MISMATCH");
            }
        }

        // Series-wide cap enforcement
        let last = decoded.last().unwrap();
        if last.public_inputs.used_out > last.public_inputs.qif_cap_mb {
            fail!(
                EACCES,
                "QIF_CAP_EXCEEDED",
                "final used_out ({}) exceeded cap ({})",
                last.public_inputs.used_out,
                last.public_inputs.qif_cap_mb
            );
        }

        Ok(decoded)
    }

    /// JSON view (`schemas/compliance-rollup-proof-v1.schema.json`).
    pub fn json_view(&self) -> Value {
        let mut v = json!({
            "v": self.v, "encoding": "cbor", "profile": self.profile,
            "public_inputs": self.public_inputs, "field": self.field,
            "fri": self.fri, "proof_bytes_len": self.proof_bytes_len,
            "padded_frame_bytes": self.padded_frame_bytes,
        });
        if let Some(c) = self.cohort_size {
            v["cohort_size"] = c.into();
        }
        if let Some(h) = self.heartbeat {
            v["heartbeat"] = h.into();
        }
        if let Some(s) = &self.hardware_batch_anchor_sigs {
            v["hardware_batch_anchor_sigs"] = json!(s);
        }
        v
    }

    /// Canonical domain-separated message signed by the L2 batch anchor (`FS-707` Phase 2).
    pub fn batch_anchor_message(stmt: &EpochStatement) -> Vec<u8> {
        let mut msg = b"depot-v3-RollupBatchAnchor-v1\0".to_vec();
        msg.extend_from_slice(&stmt.vk_digest);
        msg.push(stmt.profile);
        msg.extend_from_slice(&stmt.policy_blake3);
        msg.extend_from_slice(&stmt.tuf_snapshot_root);
        msg.extend_from_slice(&stmt.qif_cap_mb.to_le_bytes());
        msg.extend_from_slice(&stmt.r_fleet_pk);
        msg.extend_from_slice(&stmt.j_prev);
        msg.extend_from_slice(&stmt.j_curr);
        msg.extend_from_slice(&stmt.nullifier_e);
        msg.extend_from_slice(&stmt.s_start.to_le_bytes());
        msg.extend_from_slice(&stmt.s_end.to_le_bytes());
        msg.extend_from_slice(&stmt.used_in.to_le_bytes());
        msg.extend_from_slice(&stmt.used_out.to_le_bytes());
        msg
    }

    /// Sign an `L2` epoch statement with a hybrid `Ed25519 + NIST FIPS 204 ML-DSA-65`
    /// keypair, returning a `"pqc-hybrid-v1:<hex>"` string suitable for
    /// `hardware_batch_anchor_sigs`.
    pub fn sign_l2_hybrid_anchor(
        stmt: &EpochStatement,
        sk: &enclave_crypto::pqc::HybridSigningKey,
    ) -> String {
        let msg = Self::batch_anchor_message(stmt);
        let sig = sk.sign(&msg);
        format!("pqc-hybrid-v1:{}", hex::encode(sig.to_bytes()))
    }

    /// Verify that an `L2` rollup frame carries a valid hybrid `Ed25519 + ML-DSA-65`
    /// composite batch-anchor signature (`"pqc-hybrid-v1:<hex>"`) over its statement.
    /// Fails closed if missing or if either the classical `Ed25519` or post-quantum
    /// `ML-DSA-65` signature fails verification.
    pub fn verify_l2_hybrid_anchor(
        &self,
        vk: &enclave_crypto::pqc::HybridVerifyingKey,
    ) -> EnclaveResult<()> {
        if self.profile != 2 {
            fail!(
                EINVAL,
                "HYBRID_ANCHOR_PROFILE_MISMATCH",
                "Hybrid batch anchor signatures apply only to Profile L2"
            );
        }
        let sigs = self
            .hardware_batch_anchor_sigs
            .as_ref()
            .ok_or_else(|| err!(EACCES, "L2_HARDWARE_SIGS_REQUIRED"))?;
        let hex_sig = sigs
            .iter()
            .find_map(|s| s.strip_prefix("pqc-hybrid-v1:"))
            .ok_or_else(|| {
                err!(
                    EACCES,
                    "L2_HYBRID_ANCHOR_SIG_MISSING",
                    "No pqc-hybrid-v1 (Ed25519 + ML-DSA-65) signature found in hardware_batch_anchor_sigs"
                )
            })?;
        let raw =
            hex::decode(hex_sig).map_err(|_| err!(EINVAL, "L2_HYBRID_ANCHOR_SIG_HEX_INVALID"))?;
        let sig = enclave_crypto::pqc::HybridSignature::from_bytes(&raw)?;
        let stmt = self.statement()?;
        let msg = Self::batch_anchor_message(&stmt);
        vk.verify(&msg, &sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclave_crypto::pqc::HybridSigningKey;

    #[test]
    fn l2_hybrid_batch_anchor_dual_signature_roundtrip_and_tamper() {
        let nullifier_e = [0x42u8; 32];
        // Legacy transcript placeholder, NOT an authenticated QIF-tree root (F115).
        let qif_root = digest_bytes(&enclave_core::poseidon2::hash_bytes(
            b"depot-QifTree-v1",
            &nullifier_e,
        ));
        let stmt = EpochStatement {
            vk_digest: [0x11; 32],
            profile: 2,
            policy_blake3: [0x22; 32],
            tuf_snapshot_root: [0x33; 32],
            qif_cap_mb: QIF_CAP_MB,
            r_fleet_pk: [0x44; 32],
            j_prev: [0x55; 32],
            j_curr: [0x66; 32],
            nullifier_e,
            qif_root_prev: qif_root,
            qif_root_curr: qif_root,
            s_start: 0,
            s_end: 3,
            used_in: 0,
            used_out: 120,
            cohort_size: 0,
        };

        let sk = HybridSigningKey::generate();
        let vk = sk.verifying_key();
        let anchor_sig = ComplianceRollupProofV1::sign_l2_hybrid_anchor(&stmt, &sk);

        let wire = ComplianceRollupProofV1::build(
            &stmt,
            vec![0xaa; 256],
            None,
            false,
            Some(vec![anchor_sig]),
        )
        .unwrap();

        let decoded = ComplianceRollupProofV1::decode(&wire).unwrap();
        assert!(decoded.verify_l2_hybrid_anchor(&vk).is_ok());

        // Tamper with public statement field -> dual-signature verification fails closed.
        let mut tampered = decoded.clone();
        tampered.s_end = 4;
        assert!(tampered.verify_l2_hybrid_anchor(&vk).is_err());
    }
}
