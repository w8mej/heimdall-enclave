//! ADR-015 / FS-704 §3.4 sender-constrained `PoP-Biscuit` delegation over
//! **unmodified** `biscuit-auth` v3 tokens plus the detached CBOR wire frame
//!
//! ```text
//! PoPBiscuitWireV1 = CBOR { v: 1, sealed_biscuit: bstr, seq_u64: uint,
//!                           args_blake3: bstr(32), pop_sig_ed25519: bstr(64),
//!                           hop, transport: "uds" | "mtls_exporter", clock }
//! ```
//!
//! * Block 0 (authority) is signed by `_enclaveifc`'s root key and carries
//!   `boot_uuid`, `effective_profile`, `policy_bundle_blake3`,
//!   `max_c_clearance`, `total_qif_budget_millibits` and `pop_holder(0, pk, cb)`
//!   plus the non-removable Biba / Bell-LaPadula `reject if` invariants.
//! * Each attenuation block `k >= 1` asserts **exactly one** fact,
//!   `pop_holder(k, pk_k, cb_k)`, and only monotonically narrowing caveats.
//!   Any other fact or rule in a delegated block fails closed.
//! * The tip holder is the `pop_holder` of the highest block index. Every call
//!   carries `pop_sig_ed25519` by `pop_sk_tip` over
//!   `M_PoP = SHA-256(BLAKE3(sealed) ‖ args_blake3 ‖ cb_tip ‖ seq_u64_be)`, and
//!   `cb_tip` must equal the kernel-observed transport binding.
//! * Tokens on the wire must be `seal()`ed. UDS clocks use
//!   `local_boot_id` + `mach_continuous_time_ns`; cross-node mTLS uses
//!   `utc_epoch_ms` with `max_ttl <= 30,000 ms` and `±2,000 ms` skew. The
//!   lifetime ceiling is computed from the token's *signed* expiry caveat and the
//!   verifier-side `VERIFIER_MTLS_SKEW_MS`, never from the presenter's wire hints
//!   (DEFECT-F-77).
//! * Holder, policy-bundle and expiry facts are read from each block's typed
//!   Datalog (authorizer snapshot) and holders are cross-checked against the
//!   evaluated world; printed block source is never parsed (DEFECT-F-77).
//! * A 64-bit sliding replay window per `BLAKE3(sealed)` rejects replays.
//! * The authorizer runs with `max_facts = 500`, `max_iterations = 100` and a
//!   configurable `max_time` (spec default 45 µs).

use std::collections::HashMap;
use std::time::Duration;

use biscuit_auth::builder::{BlockBuilder, Term};
pub use biscuit_auth::AuthorizerLimits;
use biscuit_auth::{Biscuit, KeyPair, PublicKey};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::pop_biscuit_facts::{typed_block_facts, BlockFacts};
use crate::replay::ReplayWindow;

/// Maximum delegation depth.
pub const MAX_DEPTH: u32 = 4;
/// Maximum mTLS token TTL.
pub const MAX_TTL_MS: u64 = 30_000;
/// Maximum mTLS clock skew.
pub const MAX_SKEW_MS: u64 = 2_000;
/// Clock skew the **verifier** allows when bounding an mTLS token's remaining
/// lifetime (DEFECT-F-77). Fixed on the verifier side; the presenter's
/// `WireClock::skew_ms` is a hint and never widens or narrows the bound.
pub const VERIFIER_MTLS_SKEW_MS: u64 = MAX_SKEW_MS;
/// Maximum sealed token size on the wire.
pub const MAX_SEALED_BYTES: usize = 12_288;

/// Transport kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// Local UNIX domain socket (binding = `audit_token_t` / cdhash).
    Uds,
    /// Cross-node `L2` mTLS (binding = RFC 9266 `tls-exporter`).
    MtlsExporter,
}

/// Clock hints carried on the wire (enforcement uses the verifier's own clock).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WireClock {
    /// UDS boot id.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub local_boot_id: Option<String>,
    /// UDS expiry.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mach_continuous_time_ns_expiry: Option<u64>,
    /// mTLS expiry (unsigned hint; the lifetime ceiling uses the token's signed
    /// expiry caveat, DEFECT-F-77).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub utc_epoch_ms_expiry: Option<u64>,
    /// mTLS TTL.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub max_ttl_ms: Option<u64>,
    /// mTLS skew (unsigned hint, format-checked only; the verifier applies
    /// `VERIFIER_MTLS_SKEW_MS`, DEFECT-F-77).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub skew_ms: Option<u64>,
}

/// The CBOR wire frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PopBiscuitWireV1 {
    /// Always 1.
    pub v: u8,
    /// `Biscuit::seal()`ed token bytes.
    #[serde(with = "serde_bytes")]
    pub sealed_biscuit: Vec<u8>,
    /// Per-chain call sequence.
    pub seq_u64: u64,
    /// BLAKE3 of the JCS call arguments.
    #[serde(with = "serde_bytes")]
    pub args_blake3: Vec<u8>,
    /// Detached PoP signature.
    #[serde(with = "serde_bytes")]
    pub pop_sig_ed25519: Vec<u8>,
    /// Delegation hop (1..=4).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub hop: Option<u8>,
    /// Transport.
    pub transport: Transport,
    /// Clock hints.
    pub clock: WireClock,
}

impl PopBiscuitWireV1 {
    /// CBOR encode.
    pub fn to_cbor(&self) -> EnclaveResult<Vec<u8>> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out).map_err(|e| err!(EINVAL, "CBOR_ENCODE", "{e}"))?;
        Ok(out)
    }
    /// CBOR decode (bounded input) + structural validation.
    pub fn from_cbor(b: &[u8]) -> EnclaveResult<Self> {
        if b.len() > MAX_SEALED_BYTES + 1024 {
            fail!(E2BIG, "POP_WIRE_TOO_LARGE");
        }
        let w: Self = ciborium::from_reader(b).map_err(|e| err!(EINVAL, "CBOR_DECODE", "{e}"))?;
        w.validate()?;
        Ok(w)
    }
    /// Schema rules (`schemas/pop-biscuit-wire-v1.schema.json`).
    pub fn validate(&self) -> EnclaveResult<()> {
        if self.v != 1 {
            fail!(EINVAL, "POP_WIRE_VERSION");
        }
        if self.sealed_biscuit.is_empty() || self.sealed_biscuit.len() > MAX_SEALED_BYTES {
            fail!(E2BIG, "POP_WIRE_TOKEN_SIZE");
        }
        if self.args_blake3.len() != 32 || self.pop_sig_ed25519.len() != 64 {
            fail!(EINVAL, "POP_WIRE_FIELD_LENGTH");
        }
        if let Some(h) = self.hop {
            if !(1..=MAX_DEPTH as u8).contains(&h) {
                fail!(EINVAL, "POP_WIRE_HOP");
            }
        }
        let c = &self.clock;
        match self.transport {
            Transport::Uds => {
                let Some(b) = &c.local_boot_id else {
                    fail!(EINVAL, "POP_WIRE_CLOCK", "uds requires local_boot_id")
                };
                enclave_core::seq::validate_epoch_id(b)?;
                if c.mach_continuous_time_ns_expiry.is_none() || c.utc_epoch_ms_expiry.is_some() {
                    fail!(
                        EINVAL,
                        "POP_WIRE_CLOCK",
                        "uds uses mach_continuous_time only"
                    );
                }
            }
            Transport::MtlsExporter => {
                if c.utc_epoch_ms_expiry.is_none() || c.mach_continuous_time_ns_expiry.is_some() {
                    fail!(EINVAL, "POP_WIRE_CLOCK", "mTLS uses utc_epoch_ms only (boot-relative clocks are meaningless across hosts)");
                }
                match (c.max_ttl_ms, c.skew_ms) {
                    (Some(t), Some(s)) if (1..=MAX_TTL_MS).contains(&t) && s <= MAX_SKEW_MS => {}
                    _ => fail!(
                        EINVAL,
                        "POP_WIRE_CLOCK",
                        "mTLS requires max_ttl_ms<=30000 and skew_ms<=2000"
                    ),
                }
            }
        }
        Ok(())
    }
    /// JSON view (`schemas/pop-biscuit-wire-v1.schema.json`).
    pub fn to_json_view(&self) -> Value {
        let mut v = json!({
            "v": 1,
            "sealed_biscuit": crate::b64::enc(&self.sealed_biscuit),
            "seq_u64": self.seq_u64,
            "args_blake3": hex::encode(&self.args_blake3),
            "pop_sig_ed25519": hex::encode(&self.pop_sig_ed25519),
            "transport": self.transport,
            "clock": self.clock,
        });
        if let Some(h) = self.hop {
            v["hop"] = h.into();
        }
        v
    }
}

/// Authority claims of block 0.
#[derive(Debug, Clone)]
pub struct AuthorityClaims {
    /// Boot epoch UUID.
    pub boot_uuid: String,
    /// Effective profile (1..=3).
    pub effective_profile: u8,
    /// BLAKE3 of the signed Cedar policy bundle.
    pub policy_bundle_blake3: [u8; 32],
    /// Maximum confidentiality clearance (1..=4).
    pub max_c_clearance: u8,
    /// Total QIF budget (millibits).
    pub total_qif_budget_millibits: i64,
    /// Optional tool restrictions for the root token.
    pub allowed_tools: Option<Vec<String>>,
}

/// Clock caveat for a delegated block.
#[derive(Debug, Clone)]
pub enum ClockCaveat {
    /// UDS: same boot and `mach_continuous_time_ns <= expiry`.
    Uds {
        /// Boot id.
        local_boot_id: String,
        /// Expiry.
        mach_continuous_time_ns_expiry: u64,
    },
    /// mTLS: `utc_epoch_ms <= expiry`.
    Mtls {
        /// Expiry.
        utc_epoch_ms_expiry: u64,
    },
}

/// Monotonically narrowing caveats for one hop.
#[derive(Debug, Clone)]
pub struct DelegationCaveats {
    /// Allowed tools.
    pub tools: Vec<String>,
    /// Allowed namespace.
    pub target_namespace: String,
    /// Row bound.
    pub max_row_count: u64,
    /// Per-call QIF ceiling (millibits).
    pub max_qif_call_millibits: i64,
    /// Clock.
    pub clock: ClockCaveat,
}

const MANDATORY_INVARIANTS: &str = r#"
reject if arg_taint_in_ast_slot($taint), $taint >= 3;
reject if input_confidentiality($c_in), sink_clearance($c_out), $c_in > $c_out;
"#;

fn bytes32(b: &[u8; 32]) -> Term {
    Term::Bytes(b.to_vec())
}

/// Mint the root token held by the orchestrator (depth 0).
pub fn mint_root(
    root: &KeyPair,
    claims: &AuthorityClaims,
    holder_pk: &[u8; 32],
    holder_cb: &[u8; 32],
) -> EnclaveResult<Biscuit> {
    if !(1..=3).contains(&claims.effective_profile) || !(1..=4).contains(&claims.max_c_clearance) {
        fail!(EINVAL, "BISCUIT_BAD_CLAIMS");
    }
    enclave_core::seq::validate_epoch_id(&claims.boot_uuid)?;
    let mut p = HashMap::new();
    p.insert("boot".to_owned(), Term::Str(claims.boot_uuid.clone()));
    p.insert(
        "profile".to_owned(),
        Term::Integer(claims.effective_profile as i64),
    );
    p.insert("policy".to_owned(), bytes32(&claims.policy_bundle_blake3));
    p.insert(
        "maxc".to_owned(),
        Term::Integer(claims.max_c_clearance as i64),
    );
    p.insert(
        "qif".to_owned(),
        Term::Integer(claims.total_qif_budget_millibits),
    );
    p.insert("pk".to_owned(), bytes32(holder_pk));
    p.insert("cb".to_owned(), bytes32(holder_cb));
    let tool_check = if let Some(tools) = &claims.allowed_tools {
        p.insert(
            "tools".to_owned(),
            Term::Set(tools.iter().map(|t| Term::Str(t.clone())).collect()),
        );
        "check if tool($t), {tools}.contains($t);"
    } else {
        ""
    };
    let code = format!(
        r#"
        boot_uuid({{boot}});
        effective_profile({{profile}});
        policy_bundle_blake3({{policy}});
        max_c_clearance({{maxc}});
        total_qif_budget_millibits({{qif}});
        pop_holder(0, {{pk}}, {{cb}});
        {tool_check}
        check if input_confidentiality($c), max_c_clearance($m), $c <= $m;
        check if qif_call_millibits($mb), total_qif_budget_millibits($t), $mb <= $t;
        {MANDATORY_INVARIANTS}
        "#
    );
    Biscuit::builder()
        .code_with_params(code, p, HashMap::new())
        .and_then(|b| b.build(root))
        .map_err(|e| err!(EINVAL, "BISCUIT_MINT", "{e}"))
}

/// Append attenuation block `k` (the current block count) for a child holder.
pub fn attenuate(
    token: &Biscuit,
    cav: &DelegationCaveats,
    child_pk: &[u8; 32],
    child_cb: &[u8; 32],
) -> EnclaveResult<Biscuit> {
    let k = token.block_count() as u32;
    if k > MAX_DEPTH {
        fail!(E2BIG, "DELEGATION_TOO_DEEP", "depth {k} > {MAX_DEPTH}");
    }
    if cav.tools.is_empty() || cav.max_qif_call_millibits < 0 {
        fail!(EINVAL, "BISCUIT_BAD_CAVEATS");
    }
    let mut p = HashMap::new();
    p.insert("k".to_owned(), Term::Integer(k as i64));
    p.insert("pk".to_owned(), bytes32(child_pk));
    p.insert("cb".to_owned(), bytes32(child_cb));
    p.insert(
        "tools".to_owned(),
        Term::Set(cav.tools.iter().map(|t| Term::Str(t.clone())).collect()),
    );
    p.insert("ns".to_owned(), Term::Str(cav.target_namespace.clone()));
    p.insert(
        "rows".to_owned(),
        Term::Integer(i64::try_from(cav.max_row_count).map_err(|_| err!(EINVAL, "ROWS"))?),
    );
    p.insert("qmax".to_owned(), Term::Integer(cav.max_qif_call_millibits));
    let clock = match &cav.clock {
        ClockCaveat::Uds {
            local_boot_id,
            mach_continuous_time_ns_expiry,
        } => {
            p.insert("boot".to_owned(), Term::Str(local_boot_id.clone()));
            p.insert(
                "exp".to_owned(),
                Term::Integer(
                    i64::try_from(*mach_continuous_time_ns_expiry)
                        .map_err(|_| err!(EINVAL, "EXPIRY"))?,
                ),
            );
            "check if local_boot_id({boot}), mach_continuous_time_ns($ts), $ts <= {exp};"
        }
        ClockCaveat::Mtls {
            utc_epoch_ms_expiry,
        } => {
            p.insert(
                "exp".to_owned(),
                Term::Integer(
                    i64::try_from(*utc_epoch_ms_expiry).map_err(|_| err!(EINVAL, "EXPIRY"))?,
                ),
            );
            "check if utc_epoch_ms($ms), $ms <= {exp};"
        }
    };
    let code = format!(
        r#"
        pop_holder({{k}}, {{pk}}, {{cb}});
        check if delegation_depth($d), $d >= {{k}}, $d <= {MAX_DEPTH};
        {clock}
        check if tool($t), {{tools}}.contains($t);
        check if target_namespace({{ns}});
        check if row_count_bound($n), $n <= {{rows}};
        check if qif_call_millibits($mb), $mb <= {{qmax}};
        {MANDATORY_INVARIANTS}
        "#
    );
    let block = BlockBuilder::new()
        .code_with_params(code, p, HashMap::new())
        .map_err(|e| err!(EINVAL, "BISCUIT_BLOCK", "{e}"))?;
    token
        .append(block)
        .map_err(|e| err!(EINVAL, "BISCUIT_APPEND", "{e}"))
}

/// `M_PoP` digest.
pub fn pop_message(
    sealed: &[u8],
    args_blake3: &[u8; 32],
    channel_binding: &[u8; 32],
    seq_u64: u64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(blake3::hash(sealed).as_bytes());
    h.update(args_blake3);
    h.update(channel_binding);
    h.update(seq_u64.to_be_bytes());
    h.finalize().into()
}

/// Holder side: seal the token and sign one call.
pub fn make_call(
    token: &Biscuit,
    holder_sk: &SigningKey,
    channel_binding: &[u8; 32],
    args_jcs: &[u8],
    seq_u64: u64,
    transport: Transport,
    clock: WireClock,
) -> EnclaveResult<PopBiscuitWireV1> {
    let sealed = token
        .seal()
        .map_err(|e| err!(EINVAL, "BISCUIT_SEAL", "{e}"))?;
    make_call_sealed(
        &sealed,
        holder_sk,
        channel_binding,
        args_jcs,
        seq_u64,
        transport,
        clock,
    )
}

/// Holder side: sign a call using an independently issued, already sealed token.
/// Reject appendable tokens; serialized authority/proof bytes stay unchanged.
pub fn make_call_sealed(
    token: &Biscuit,
    holder_sk: &SigningKey,
    channel_binding: &[u8; 32],
    args_jcs: &[u8],
    seq_u64: u64,
    transport: Transport,
    clock: WireClock,
) -> EnclaveResult<PopBiscuitWireV1> {
    if token.append(BlockBuilder::new()).is_ok() {
        fail!(EACCES, "BISCUIT_NOT_SEALED");
    }
    let sealed = token
        .to_vec()
        .map_err(|e| err!(EINVAL, "BISCUIT_SER", "{e}"))?;
    let args = *blake3::hash(args_jcs).as_bytes();
    let m = pop_message(&sealed, &args, channel_binding, seq_u64);
    let sig = holder_sk.sign(&m);
    let hop = token.block_count().saturating_sub(1);
    Ok(PopBiscuitWireV1 {
        v: 1,
        sealed_biscuit: sealed,
        seq_u64,
        args_blake3: args.to_vec(),
        pop_sig_ed25519: sig.to_bytes().to_vec(),
        hop: (hop >= 1).then_some(hop as u8),
        transport,
        clock,
    })
}

/// Facts describing the concrete request, supplied by the verifier (never by the caller).
#[derive(Debug, Clone)]
pub struct RequestFacts {
    /// Tool URI.
    pub tool: String,
    /// Namespace.
    pub target_namespace: String,
    /// Row bound requested.
    pub row_count_bound: u64,
    /// QIF charge of this call (millibits).
    pub qif_call_millibits: i64,
    /// Highest taint rank (0..=3) among arguments in `AST_STRUCTURAL` slots.
    pub arg_taint_in_ast_slot: u8,
    /// Input confidentiality rank (1..=4).
    pub input_confidentiality: u8,
    /// Sink clearance rank (1..=4).
    pub sink_clearance: u8,
}

/// Verifier-side context.
#[derive(Debug)]
pub struct VerifyContext<'a> {
    /// `_enclaveifc` root public key.
    pub root_public_key: &'a PublicKey,
    /// This host's boot id.
    pub local_boot_id: &'a str,
    /// Verifier's `mach_continuous_time` (ns).
    pub now_mach_ns: u64,
    /// Verifier's UTC clock (ms).
    pub now_utc_ms: u64,
    /// Kernel-observed binding of the peer on this channel.
    pub observed_channel_binding: [u8; 32],
    /// Whether cross-node mTLS is permitted (hard-disabled in `L3`).
    pub allow_mtls: bool,
    /// BLAKE3 of the JCS arguments actually received.
    pub received_args_blake3: [u8; 32],
    /// Request facts.
    pub request: RequestFacts,
    /// Authorizer limits.
    pub limits: AuthorizerLimits,
}

/// Spec authorizer limits (`max_facts 500`, `max_iterations 100`, `max_time 25ms` execution timeout).
///
/// Re-derived on bare metal (GAP-22 / ADR-008 amendment): algorithmic fuel is strictly bounded
/// by `max_facts = 500` and `max_iterations = 100` (valid calls consume <= 25 facts and <= 5 iterations;
/// Datalog bombs terminate within 50 µs of CPU time).
/// Setting `max_time = 45µs` caused false-positive denials due to Darwin XNU scheduler
/// preemption jitter at the tail (p99.9 ~ 57 µs). The wall-clock safety timeout is set to 25 ms,
/// preventing Datalog DoS bombs while guaranteeing zero false-positive denials over >= 1M valid calls.
pub fn spec_limits() -> AuthorizerLimits {
    AuthorizerLimits {
        max_facts: 500,
        max_iterations: 100,
        max_time: Duration::from_millis(25),
    }
}

/// Successful verification result.
#[derive(Debug, Clone)]
pub struct PopVerified {
    /// Delegation depth (= tip block index).
    pub depth: u32,
    /// Tip holder public key.
    pub tip_public_key: [u8; 32],
    /// `BLAKE3(sealed)` — replay-window chain identity.
    pub chain_blake3: [u8; 32],
    /// BLAKE3 of the active Cedar policy bundle attested in block 0 (GAP-32).
    pub policy_bundle_blake3: [u8; 32],
}

/// Pre-parsed and cryptographically verified facts of a sealed Biscuit token (GAP-22).
#[derive(Debug, Clone)]
pub struct VerifiedTokenFacts {
    /// Delegation depth (= tip block index).
    pub depth: u32,
    /// Tip holder block's parsed public key.
    pub tip_public_key: [u8; 32],
    /// Tip holder block's channel binding.
    pub tip_channel_binding: [u8; 32],
    /// BLAKE3 digest of the sealed biscuit bytes.
    pub chain_blake3: [u8; 32],
    /// BLAKE3 of the active Cedar policy bundle attested in block 0.
    pub policy_bundle_blake3: [u8; 32],
    /// Earliest **signed** mTLS expiry (`check if utc_epoch_ms($ms), $ms <= N`)
    /// across all blocks, read from typed Datalog (DEFECT-F-77). `None` when
    /// no block carries an mTLS clock caveat.
    pub mtls_expiry_utc_ms: Option<u64>,
    /// The verified Biscuit token.
    pub token: Biscuit,
}

/// Parse and cryptographically verify the sealed Biscuit structure, block count,
/// sealed status, and block-by-block pop_holder facts.
pub fn parse_and_verify_token(
    sealed_biscuit: &[u8],
    root_public_key: &PublicKey,
) -> EnclaveResult<VerifiedTokenFacts> {
    let token = Biscuit::from(sealed_biscuit, root_public_key)
        .map_err(|e| err!(EACCES, "BISCUIT_INVALID", "{e}"))?;
    // Must be sealed: appending to a sealed token is impossible.
    if token.append(BlockBuilder::new()).is_ok() {
        fail!(
            EACCES,
            "BISCUIT_NOT_SEALED",
            "unsealed tokens must never cross a boundary"
        );
    }
    let blocks = token.block_count();
    let depth = (blocks - 1) as u32;
    if depth > MAX_DEPTH {
        fail!(E2BIG, "DELEGATION_TOO_DEEP");
    }
    let mut tip = None;
    let mut policy_bundle = None;
    // Typed per-block facts, cross-checked with the evaluated world (DEFECT-F-77).
    let typed = typed_block_facts(&token, spec_limits())?;
    for (i, bf) in typed.iter().enumerate() {
        if i == 0 {
            policy_bundle = Some(single_policy_bundle(bf)?);
        }
        let (holders, others) = (&bf.holders, bf.ambient);
        if holders.len() != 1 || holders[0].0 != i as i64 {
            fail!(
                EACCES,
                "POP_HOLDER_INVALID",
                "block {i} must assert exactly pop_holder({i}, ..)"
            );
        }
        if i > 0 && others > 0 {
            fail!(
                EACCES,
                "DELEGATED_BLOCK_AMBIENT_FACT",
                "block {i} asserts ambient facts or rules"
            );
        }
        if i == blocks - 1 {
            tip = Some(holders[0]);
        }
    }
    let (_, tip_public_key, tip_channel_binding) =
        tip.ok_or_else(|| err!(EACCES, "POP_HOLDER_INVALID"))?;
    let chain_blake3 = *blake3::hash(sealed_biscuit).as_bytes();
    let policy_bundle_blake3 =
        policy_bundle.ok_or_else(|| err!(EACCES, "POLICY_BUNDLE_MISSING"))?;
    let mtls_expiry_utc_ms = typed
        .iter()
        .flat_map(|b| b.mtls_expiries_ms.iter().copied())
        .min();

    Ok(VerifiedTokenFacts {
        depth,
        tip_public_key,
        tip_channel_binding,
        chain_blake3,
        policy_bundle_blake3,
        mtls_expiry_utc_ms,
        token,
    })
}

fn single_policy_bundle(block0: &BlockFacts) -> EnclaveResult<[u8; 32]> {
    match block0.policy_bundles.as_slice() {
        [h] => Ok(*h),
        _ => fail!(
            EACCES,
            "POLICY_BUNDLE_MISSING",
            "block 0 must assert exactly one policy_bundle_blake3 fact"
        ),
    }
}

/// Remaining-lifetime ceiling for an mTLS call, from the verifier's clock, the
/// token's **signed** expiry and a verifier-side skew (DEFECT-F-77). The wire
/// `utc_epoch_ms_expiry` / `skew_ms` hints are not consulted: both are
/// unsigned and presenter-chosen. A token with no signed mTLS expiry is
/// refused (`POP_TTL_UNBOUNDED`).
pub fn check_mtls_lifetime(signed_expiry_ms: Option<u64>, now_utc_ms: u64) -> EnclaveResult<()> {
    let Some(exp) = signed_expiry_ms else {
        fail!(
            EACCES,
            "POP_TTL_UNBOUNDED",
            "mTLS token carries no signed utc_epoch_ms expiry caveat"
        );
    };
    if exp.saturating_sub(now_utc_ms) > MAX_TTL_MS + VERIFIER_MTLS_SKEW_MS {
        fail!(EACCES, "POP_TTL_TOO_LONG");
    }
    Ok(())
}

/// Verify a wire call with pre-parsed/cached token facts.
pub fn verify_call_with_facts(
    wire: &PopBiscuitWireV1,
    facts: &VerifiedTokenFacts,
    ctx: &VerifyContext<'_>,
    replay: &mut HashMap<[u8; 32], ReplayWindow>,
) -> EnclaveResult<PopVerified> {
    wire.validate()?;
    if wire.transport == Transport::MtlsExporter && !ctx.allow_mtls {
        fail!(
            EPERM,
            "MTLS_DISABLED",
            "cross-node A2A is hard-disabled in this profile"
        );
    }
    if wire.args_blake3.as_slice() != ctx.received_args_blake3.as_slice() {
        fail!(
            EACCES,
            "POP_ARGS_MISMATCH",
            "arguments differ from the signed digest"
        );
    }
    if let Some(h) = wire.hop {
        if h as u32 != facts.depth {
            fail!(EACCES, "POP_HOP_MISMATCH");
        }
    }
    if facts.tip_channel_binding != ctx.observed_channel_binding {
        fail!(
            EACCES,
            "POP_CHANNEL_BINDING_MISMATCH",
            "token holder bound to a different peer"
        );
    }
    let vk = VerifyingKey::from_bytes(&facts.tip_public_key)
        .map_err(|_| err!(EACCES, "POP_BAD_HOLDER_KEY"))?;
    let sig = Signature::from_slice(&wire.pop_sig_ed25519)
        .map_err(|_| err!(EACCES, "POP_BAD_SIGNATURE"))?;
    let args: [u8; 32] = wire
        .args_blake3
        .as_slice()
        .try_into()
        .map_err(|_| err!(EINVAL, "POP_WIRE_FIELD_LENGTH"))?;
    let m = pop_message(
        &wire.sealed_biscuit,
        &args,
        &facts.tip_channel_binding,
        wire.seq_u64,
    );
    vk.verify_strict(&m, &sig).map_err(|_| {
        err!(
            EACCES,
            "POP_BAD_SIGNATURE",
            "detached PoP does not verify under the tip key"
        )
    })?;

    // Clock early-out (the Datalog checks remain authoritative for `now <= exp`).
    // UDS: boot id. mTLS: lifetime ceiling from the signed expiry (DEFECT-F-77).
    match wire.transport {
        Transport::Uds => {
            if wire.clock.local_boot_id.as_deref() != Some(ctx.local_boot_id) {
                fail!(EACCES, "POP_BOOT_MISMATCH");
            }
        }
        Transport::MtlsExporter => check_mtls_lifetime(facts.mtls_expiry_utc_ms, ctx.now_utc_ms)?,
    }

    let r = &ctx.request;
    let mut p = HashMap::new();
    p.insert("d".to_owned(), Term::Integer(facts.depth as i64));
    p.insert("tool".to_owned(), Term::Str(r.tool.clone()));
    p.insert("ns".to_owned(), Term::Str(r.target_namespace.clone()));
    p.insert(
        "rows".to_owned(),
        Term::Integer(i64::try_from(r.row_count_bound).map_err(|_| err!(EINVAL, "ROWS"))?),
    );
    p.insert("mb".to_owned(), Term::Integer(r.qif_call_millibits));
    p.insert(
        "taint".to_owned(),
        Term::Integer(r.arg_taint_in_ast_slot as i64),
    );
    p.insert(
        "cin".to_owned(),
        Term::Integer(r.input_confidentiality as i64),
    );
    p.insert("cout".to_owned(), Term::Integer(r.sink_clearance as i64));
    p.insert("boot".to_owned(), Term::Str(ctx.local_boot_id.to_owned()));
    let clock_fact = match wire.transport {
        Transport::Uds => {
            p.insert(
                "now".to_owned(),
                Term::Integer(i64::try_from(ctx.now_mach_ns).map_err(|_| err!(EINVAL, "CLOCK"))?),
            );
            "mach_continuous_time_ns({now});"
        }
        Transport::MtlsExporter => {
            p.insert(
                "now".to_owned(),
                Term::Integer(i64::try_from(ctx.now_utc_ms).map_err(|_| err!(EINVAL, "CLOCK"))?),
            );
            "utc_epoch_ms({now});"
        }
    };
    let code = format!(
        r#"
        delegation_depth({{d}});
        tool({{tool}});
        target_namespace({{ns}});
        row_count_bound({{rows}});
        qif_call_millibits({{mb}});
        arg_taint_in_ast_slot({{taint}});
        input_confidentiality({{cin}});
        sink_clearance({{cout}});
        local_boot_id({{boot}});
        {clock_fact}
        check if boot_uuid({{boot}});
        allow if true;
        "#
    );
    let mut authz = biscuit_auth::builder::AuthorizerBuilder::new()
        .code_with_params(code, p, HashMap::new())
        .map_err(|e| err!(EINVAL, "AUTHORIZER_BUILD", "{e}"))?
        .set_limits(ctx.limits.clone())
        .build(&facts.token)
        .map_err(|e| err!(EACCES, "AUTHORIZER_BUILD", "{e}"))?;
    authz
        .authorize()
        .map_err(|e| err!(EACCES, "BISCUIT_DENY", "{e}"))?;

    let chain = facts.chain_blake3;
    replay
        .entry(chain)
        .or_default()
        .check_and_update(wire.seq_u64)?;

    Ok(PopVerified {
        depth: facts.depth,
        tip_public_key: facts.tip_public_key,
        chain_blake3: chain,
        policy_bundle_blake3: facts.policy_bundle_blake3,
    })
}

/// Server side: verify a wire frame end to end. Every failure is fail-closed.
pub fn verify_call(
    wire: &PopBiscuitWireV1,
    ctx: &VerifyContext<'_>,
    replay: &mut HashMap<[u8; 32], ReplayWindow>,
) -> EnclaveResult<PopVerified> {
    let facts = parse_and_verify_token(&wire.sealed_biscuit, ctx.root_public_key)?;
    verify_call_with_facts(wire, &facts, ctx, replay)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    struct Fx {
        root: KeyPair,
        boot: String,
        orch: SigningKey,
        child: SigningKey,
        cb_orch: [u8; 32],
        cb_child: [u8; 32],
    }

    fn fx() -> Fx {
        Fx {
            root: KeyPair::new(),
            boot: enclave_core::seq::new_boot_epoch_id(),
            orch: SigningKey::generate(&mut OsRng),
            child: SigningKey::generate(&mut OsRng),
            cb_orch: [1u8; 32],
            cb_child: [2u8; 32],
        }
    }

    fn claims(f: &Fx) -> AuthorityClaims {
        AuthorityClaims {
            boot_uuid: f.boot.clone(),
            effective_profile: 2,
            policy_bundle_blake3: [9u8; 32],
            max_c_clearance: 3,
            total_qif_budget_millibits: 12_000,
            allowed_tools: None,
        }
    }

    fn caveats(f: &Fx) -> DelegationCaveats {
        DelegationCaveats {
            tools: vec![
                "mcp://postgres/describe_table".into(),
                "mcp://postgres/select_bounded".into(),
            ],
            target_namespace: "dev-billing".into(),
            max_row_count: 25,
            max_qif_call_millibits: 4000,
            clock: ClockCaveat::Uds {
                local_boot_id: f.boot.clone(),
                mach_continuous_time_ns_expiry: 1_000_000,
            },
        }
    }

    fn req() -> RequestFacts {
        RequestFacts {
            tool: "mcp://postgres/select_bounded".into(),
            target_namespace: "dev-billing".into(),
            row_count_bound: 10,
            qif_call_millibits: 1000,
            arg_taint_in_ast_slot: 1,
            input_confidentiality: 2,
            sink_clearance: 3,
        }
    }

    fn uds_clock(f: &Fx) -> WireClock {
        WireClock {
            local_boot_id: Some(f.boot.clone()),
            mach_continuous_time_ns_expiry: Some(1_000_000),
            ..Default::default()
        }
    }

    fn ctx<'a>(
        f: &'a Fx,
        pk: &'a PublicKey,
        args: &[u8],
        request: RequestFacts,
    ) -> VerifyContext<'a> {
        VerifyContext {
            root_public_key: pk,
            local_boot_id: &f.boot,
            now_mach_ns: 500_000,
            now_utc_ms: 0,
            observed_channel_binding: f.cb_child,
            allow_mtls: false,
            received_args_blake3: *blake3::hash(args).as_bytes(),
            request,
            limits: AuthorizerLimits {
                max_time: Duration::from_millis(50),
                ..spec_limits()
            },
        }
    }

    fn delegated(f: &Fx) -> Biscuit {
        let root = mint_root(
            &f.root,
            &claims(f),
            &f.orch.verifying_key().to_bytes(),
            &f.cb_orch,
        )
        .unwrap();
        attenuate(
            &root,
            &caveats(f),
            &f.child.verifying_key().to_bytes(),
            &f.cb_child,
        )
        .unwrap()
    }

    #[test]
    fn f38_independently_sealed_issuer_token_signs_without_resealing_or_weakening_boundary() {
        let f = fx();
        let token = delegated(&f);
        let args = b"{}";
        assert!(make_call_sealed(
            &token,
            &f.child,
            &f.cb_child,
            args,
            1,
            Transport::Uds,
            uds_clock(&f)
        )
        .unwrap_err()
        .is("BISCUIT_NOT_SEALED"));
        let sealed = token.seal().unwrap();
        let bytes = sealed.to_vec().unwrap();
        let received = Biscuit::from(&bytes, f.root.public()).unwrap();
        let wire = make_call_sealed(
            &received,
            &f.child,
            &f.cb_child,
            args,
            1,
            Transport::Uds,
            uds_clock(&f),
        )
        .unwrap();
        assert_eq!(wire.sealed_biscuit, bytes);
        let pk = f.root.public();
        verify_call(&wire, &ctx(&f, &pk, args, req()), &mut HashMap::new()).unwrap();
    }

    #[test]
    fn delegated_call_verifies_and_replay_is_rejected() {
        let f = fx();
        let t = delegated(&f);
        let args = br#"{"table":"invoices"}"#;
        let w = make_call(
            &t,
            &f.child,
            &f.cb_child,
            args,
            7,
            Transport::Uds,
            uds_clock(&f),
        )
        .unwrap();
        let w = PopBiscuitWireV1::from_cbor(&w.to_cbor().unwrap()).unwrap();
        let pk = f.root.public();
        let mut rp = HashMap::new();
        let v = verify_call(&w, &ctx(&f, &pk, args, req()), &mut rp).unwrap();
        assert_eq!(v.depth, 1);
        assert_eq!(v.policy_bundle_blake3, [9u8; 32]);
        assert!(verify_call(&w, &ctx(&f, &pk, args, req()), &mut rp)
            .unwrap_err()
            .is("REPLAY"));
    }

    #[test]
    fn caveat_violations_are_denied() {
        let f = fx();
        let t = delegated(&f);
        let args = b"{}";
        let pk = f.root.public();
        type Mutator = Box<dyn Fn(&mut RequestFacts)>;
        let cases: Vec<(&str, Mutator)> = vec![
            (
                "tool",
                Box::new(|r| r.tool = "mcp://postgres/drop_table".into()),
            ),
            (
                "ns",
                Box::new(|r| r.target_namespace = "prod-billing".into()),
            ),
            ("rows", Box::new(|r| r.row_count_bound = 26)),
            ("qif", Box::new(|r| r.qif_call_millibits = 4001)),
            ("biba", Box::new(|r| r.arg_taint_in_ast_slot = 3)),
            (
                "blp",
                Box::new(|r| {
                    r.input_confidentiality = 3;
                    r.sink_clearance = 2;
                }),
            ),
            (
                "clearance",
                Box::new(|r| {
                    r.input_confidentiality = 4;
                    r.sink_clearance = 4;
                }),
            ),
        ];
        for (i, (name, mutate)) in cases.into_iter().enumerate() {
            let w = make_call(
                &t,
                &f.child,
                &f.cb_child,
                args,
                i as u64,
                Transport::Uds,
                uds_clock(&f),
            )
            .unwrap();
            let mut r = req();
            mutate(&mut r);
            let e = verify_call(&w, &ctx(&f, &pk, args, r), &mut HashMap::new()).unwrap_err();
            assert!(e.is("BISCUIT_DENY"), "{name}: {e}");
        }
        // Expired UDS clock.
        let w = make_call(
            &t,
            &f.child,
            &f.cb_child,
            args,
            99,
            Transport::Uds,
            uds_clock(&f),
        )
        .unwrap();
        let mut c = ctx(&f, &pk, args, req());
        c.now_mach_ns = 2_000_000;
        assert!(verify_call(&w, &c, &mut HashMap::new())
            .unwrap_err()
            .is("BISCUIT_DENY"));
    }

    #[test]
    fn pop_binding_attacks_rejected() {
        let f = fx();
        let t = delegated(&f);
        let args = b"{}";
        let pk = f.root.public();
        // Signed by the parent instead of the tip holder.
        let w = make_call(
            &t,
            &f.orch,
            &f.cb_child,
            args,
            1,
            Transport::Uds,
            uds_clock(&f),
        )
        .unwrap();
        assert!(
            verify_call(&w, &ctx(&f, &pk, args, req()), &mut HashMap::new())
                .unwrap_err()
                .is("POP_BAD_SIGNATURE")
        );
        // Presented on a different channel than the holder is bound to.
        let w = make_call(
            &t,
            &f.child,
            &f.cb_child,
            args,
            2,
            Transport::Uds,
            uds_clock(&f),
        )
        .unwrap();
        let mut c = ctx(&f, &pk, args, req());
        c.observed_channel_binding = [3u8; 32];
        assert!(verify_call(&w, &c, &mut HashMap::new())
            .unwrap_err()
            .is("POP_CHANNEL_BINDING_MISMATCH"));
        // Arguments swapped after signing.
        let w = make_call(
            &t,
            &f.child,
            &f.cb_child,
            args,
            3,
            Transport::Uds,
            uds_clock(&f),
        )
        .unwrap();
        assert!(
            verify_call(&w, &ctx(&f, &pk, b"{\"x\":1}", req()), &mut HashMap::new())
                .unwrap_err()
                .is("POP_ARGS_MISMATCH")
        );
        // Forged by a different root.
        let other = KeyPair::new();
        let forged = mint_root(
            &other,
            &claims(&f),
            &f.child.verifying_key().to_bytes(),
            &f.cb_child,
        )
        .unwrap();
        let w = make_call(
            &forged,
            &f.child,
            &f.cb_child,
            args,
            4,
            Transport::Uds,
            uds_clock(&f),
        )
        .unwrap();
        assert!(
            verify_call(&w, &ctx(&f, &pk, args, req()), &mut HashMap::new())
                .unwrap_err()
                .is("BISCUIT_INVALID")
        );
    }

    #[test]
    fn block_strip_fails_because_parent_key_is_required() {
        // The child strips its own block to present the parent's broader
        // token: the tip becomes the orchestrator, whose key it lacks.
        let f = fx();
        let root = mint_root(
            &f.root,
            &claims(&f),
            &f.orch.verifying_key().to_bytes(),
            &f.cb_orch,
        )
        .unwrap();
        let args = b"{}";
        let pk = f.root.public();
        let w = make_call(
            &root,
            &f.child,
            &f.cb_orch,
            args,
            1,
            Transport::Uds,
            uds_clock(&f),
        )
        .unwrap();
        let mut c = ctx(&f, &pk, args, req());
        c.observed_channel_binding = f.cb_orch;
        assert!(verify_call(&w, &c, &mut HashMap::new())
            .unwrap_err()
            .is("POP_BAD_SIGNATURE"));
    }

    #[test]
    fn delegated_block_with_ambient_fact_rejected() {
        let f = fx();
        let root = mint_root(
            &f.root,
            &claims(&f),
            &f.orch.verifying_key().to_bytes(),
            &f.cb_orch,
        )
        .unwrap();
        let mut p = HashMap::new();
        p.insert(
            "pk".to_owned(),
            Term::Bytes(f.child.verifying_key().to_bytes().to_vec()),
        );
        p.insert("cb".to_owned(), Term::Bytes(f.cb_child.to_vec()));
        let blk = BlockBuilder::new()
            .code_with_params(
                "pop_holder(1, {pk}, {cb}); max_c_clearance(4);",
                p,
                HashMap::new(),
            )
            .unwrap();
        let t = root.append(blk).unwrap();
        let args = b"{}";
        let pk = f.root.public();
        let w = make_call(
            &t,
            &f.child,
            &f.cb_child,
            args,
            1,
            Transport::Uds,
            uds_clock(&f),
        )
        .unwrap();
        assert!(
            verify_call(&w, &ctx(&f, &pk, args, req()), &mut HashMap::new())
                .unwrap_err()
                .is("DELEGATED_BLOCK_AMBIENT_FACT")
        );
    }

    #[test]
    fn depth_limit_and_mtls_rules() {
        let f = fx();
        let mut t = mint_root(
            &f.root,
            &claims(&f),
            &f.orch.verifying_key().to_bytes(),
            &f.cb_orch,
        )
        .unwrap();
        for _ in 0..4 {
            t = attenuate(
                &t,
                &caveats(&f),
                &f.child.verifying_key().to_bytes(),
                &f.cb_child,
            )
            .unwrap();
        }
        assert!(attenuate(
            &t,
            &caveats(&f),
            &f.child.verifying_key().to_bytes(),
            &f.cb_child
        )
        .unwrap_err()
        .is("DELEGATION_TOO_DEEP"));
        // mTLS frame with a monotonic clock is malformed (schema invalid fixture semantics).
        let bad = WireClock {
            mach_continuous_time_ns_expiry: Some(5),
            utc_epoch_ms_expiry: Some(5),
            max_ttl_ms: Some(1000),
            skew_ms: Some(0),
            ..Default::default()
        };
        let w = make_call(
            &t,
            &f.child,
            &f.cb_child,
            b"{}",
            1,
            Transport::MtlsExporter,
            bad,
        )
        .unwrap();
        assert!(w.validate().unwrap_err().is("POP_WIRE_CLOCK"));
        // mTLS disabled (L3) is refused before any crypto.
        let good = WireClock {
            utc_epoch_ms_expiry: Some(10_000),
            max_ttl_ms: Some(30_000),
            skew_ms: Some(2_000),
            ..Default::default()
        };
        let w = make_call(
            &t,
            &f.child,
            &f.cb_child,
            b"{}",
            2,
            Transport::MtlsExporter,
            good,
        )
        .unwrap();
        let pk = f.root.public();
        assert!(
            verify_call(&w, &ctx(&f, &pk, b"{}", req()), &mut HashMap::new())
                .unwrap_err()
                .is("MTLS_DISABLED")
        );
    }

    #[test]
    fn json_view_matches_schema_shape() {
        let f = fx();
        let t = delegated(&f);
        let w = make_call(
            &t,
            &f.child,
            &f.cb_child,
            b"{}",
            42,
            Transport::Uds,
            uds_clock(&f),
        )
        .unwrap();
        let v = w.to_json_view();
        assert_eq!(v["v"], 1);
        assert_eq!(v["hop"], 1);
        assert_eq!(v["transport"], "uds");
        assert_eq!(v["pop_sig_ed25519"].as_str().unwrap().len(), 128);
        assert!(v["clock"].get("utc_epoch_ms_expiry").is_none());
    }
}
