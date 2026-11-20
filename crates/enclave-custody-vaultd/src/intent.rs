//! FS-703 §3.2 RFC 8785 transaction-bound `IntentPayloadV1`
//! (`schemas/intent-payload-v1.schema.json`), its digest
//! `d_JCS = SHA-256(JCS(intent))`, the trusted human summary synthesised from
//! the parsed AST (never model- or server-supplied), and the 4-word SAS.

use std::collections::BTreeSet;

use enclave_core::error::EnclaveResult;
use enclave_core::label::Conf;
use enclave_core::profile::{ActionClass, Profile};
use enclave_core::user_turn::UserTurnV1;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::factors::{required_factors, Factor};

/// Custody grant marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CustodyGrant {
    /// No reversible tokenization.
    #[serde(rename = "none")]
    None,
    /// Cedar `Custody::ReversibleTokenize`.
    #[serde(rename = "Custody::ReversibleTokenize")]
    ReversibleTokenize,
}

/// `IntentPayloadV1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentPayloadV1 {
    /// Always 1.
    pub v: u8,
    /// `enclave.intent.v1`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub schema_version: Option<String>,
    /// Action class.
    pub action_class: ActionClass,
    /// Profile.
    pub profile: Profile,
    /// Data class.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub data_class: Option<Conf>,
    /// Caller SPIFFE ID.
    pub spiffe_id: String,
    /// Tool.
    pub tool_name: String,
    /// Namespace.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub target_namespace: Option<String>,
    /// Trusted summary.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub human_summary_trusted: Option<String>,
    /// Row bound.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub row_count_bound: Option<u64>,
    /// SHA-256 of JCS(arguments).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub arguments_jcs_sha256: Option<String>,
    /// BLAKE3 of JCS(arguments).
    pub canonical_arguments_blake3: String,
    /// Model digest.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub model_blake3: Option<String>,
    /// Policy bundle digest.
    pub policy_blake3: String,
    /// QIF delta.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub qif_millibits_delta: Option<i64>,
    /// Custody grant.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub custody_grant: Option<CustodyGrant>,
    /// Boot epoch.
    pub boot_epoch_id: String,
    /// Sequence.
    pub rpc_seq_u64: u64,
    /// Wall clock.
    pub ts_utc_ms: u64,
    /// Factors.
    pub required_factors: Vec<Factor>,
    /// Originating user turn.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub user_turn: Option<UserTurnV1>,
}

fn hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Canonical sorted surrogate-list digests used by both ceremony and release.
pub(crate) fn surrogate_digests(surrogates: &[String]) -> EnclaveResult<(String, String)> {
    use sha2::Digest;
    let mut sorted=surrogates.to_vec();sorted.sort();
    let bytes=serde_json::to_vec(&sorted).map_err(|e|err!(EINVAL,"SURROGATES_JCS","{e}"))?;
    Ok((hex::encode(sha2::Sha256::digest(&bytes)),blake3::hash(&bytes).to_hex().to_string()))
}

impl IntentPayloadV1 {
    /// Both hashes must bind exactly the independently canonicalized release list.
    pub(crate) fn verify_surrogate_arguments(&self, surrogates: &[String]) -> EnclaveResult<()> {
        let (sha,b3)=surrogate_digests(surrogates)?;
        if self.canonical_arguments_blake3!=b3 || self.arguments_jcs_sha256.as_deref()!=Some(sha.as_str()) {
            fail!(EACCES,"SURROGATES_INTENT_MISMATCH");
        }
        Ok(())
    }

    /// Enforce the schema and its `allOf` rules (fail closed).
    pub fn validate(&self) -> EnclaveResult<()> {
        if self.v != 1 {
            fail!(EINVAL, "INTENT_VERSION");
        }
        if self
            .schema_version
            .as_deref()
            .is_some_and(|s| s != "enclave.intent.v1")
        {
            fail!(EINVAL, "INTENT_SCHEMA_VERSION");
        }
        let tool_ok = !self.tool_name.is_empty()
            && self.tool_name.len() <= 128
            && self
                .tool_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-' | '/'));
        if !self.spiffe_id.starts_with("spiffe://") || !tool_ok {
            fail!(EINVAL, "INTENT_IDENTITY");
        }
        for d in [
            Some(&self.canonical_arguments_blake3),
            Some(&self.policy_blake3),
            self.model_blake3.as_ref(),
            self.arguments_jcs_sha256.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if !hex64(d) {
                fail!(EINVAL, "INTENT_DIGEST");
            }
        }
        enclave_core::seq::validate_epoch_id(&self.boot_epoch_id)?;
        if let Some(q) = self.qif_millibits_delta {
            if !(0..=12_000).contains(&q) {
                fail!(EINVAL, "INTENT_QIF_RANGE");
            }
        }
        if let Some(r) = self.row_count_bound {
            if !(1..=100_000).contains(&r) {
                fail!(EINVAL, "INTENT_ROW_RANGE");
            }
            if r >= 2 && self.action_class != ActionClass::A4 {
                fail!(
                    EPERM,
                    "BULK_REQUIRES_A4",
                    "row_count_bound {r} > 1 must be A4"
                );
            }
        }
        if self
            .human_summary_trusted
            .as_ref()
            .is_some_and(|h| h.len() > 256)
            || self
                .target_namespace
                .as_ref()
                .is_some_and(|n| n.len() > 128)
        {
            fail!(EINVAL, "INTENT_FIELD_LENGTH");
        }
        let fs: BTreeSet<Factor> = self.required_factors.iter().copied().collect();
        if fs.len() != self.required_factors.len() {
            fail!(EINVAL, "INTENT_DUPLICATE_FACTOR");
        }
        if self.action_class >= ActionClass::A3 {
            if !fs.contains(&Factor::TouchIdCoreauthui) {
                fail!(
                    EPERM,
                    "INTENT_MISSING_TOUCH_ID",
                    "A3/A4 always require CoreAuthUI"
                );
            }
            if self.profile >= Profile::L2 && !fs.contains(&Factor::YubikeyUp) {
                fail!(
                    EPERM,
                    "INTENT_MISSING_YUBIKEY",
                    "L2/L3 A3/A4 require chained Touch ID -> YubiKey"
                );
            }
        }
        // The declared factors must cover the matrix (they may exceed it).
        let need = required_factors(self.profile, self.action_class, self.is_org_root_mutation());
        if !need.is_subset(&fs) {
            fail!(EPERM, "INTENT_FACTORS_BELOW_MATRIX");
        }
        if self.profile == Profile::L1 {
            if self.custody_grant.is_some_and(|g| g != CustodyGrant::None) {
                fail!(EPERM, "L1_NO_REVERSIBLE_TOKENIZATION", "ADR-007");
            }
            if self.data_class == Some(Conf::C4) {
                fail!(
                    EPERM,
                    "L1_NEVER_DETOKENIZES_C4",
                    "C4 is erased at ingress in L1"
                );
            }
        }
        if let Some(t) = &self.user_turn {
            t.validate()?;
        }
        Ok(())
    }

    /// Whether this intent mutates organization root state (TUF, pf, policy namespaces).
    pub fn is_org_root_mutation(&self) -> bool {
        crate::factors::is_org_root_mutation(&self.tool_name, self.target_namespace.as_deref())
    }

    /// `d_JCS = SHA-256(RFC8785(intent))`.
    pub fn d_jcs(&self) -> EnclaveResult<[u8; 32]> {
        Ok(Sha256::digest(enclave_core::jcs::to_jcs_bytes(self)?).into())
    }

    /// The `CoreAuthUI` `localizedReason` string: `[A4] tool on namespace (N rows) | SAS: w-w-w-w`.
    pub fn localized_reason(&self) -> EnclaveResult<String> {
        let d = self.d_jcs()?;
        let target_part = if let Some(target) = self.target_namespace.as_deref() {
            format!(" on {target}")
        } else {
            String::new()
        };
        Ok(format!(
            "[{:?}] {}{} ({} rows) | SAS: {}",
            self.action_class,
            self.tool_name,
            target_part,
            self.row_count_bound.unwrap_or(1),
            enclave_crypto::sas::sas_words(&d)
        ))
    }
}

/// Synthesise `human_summary_trusted` deterministically from parsed AST
/// fields inside the trusted proxy (never from model or MCP-server text).
pub fn synthesize_summary(
    canonical_verb: &str,
    row_count_bound: u64,
    data_class: Conf,
    tool_name: &str,
) -> EnclaveResult<String> {
    let verb_ok =
        !canonical_verb.is_empty() && canonical_verb.bytes().all(|b| b.is_ascii_alphabetic());
    if !verb_ok || tool_name.chars().any(char::is_control) {
        return Err(err!(EINVAL, "SUMMARY_INPUT"));
    }
    let s = format!("{canonical_verb} <= {row_count_bound} {data_class:?} rows via {tool_name}");
    if s.len() > 256 {
        fail!(E2BIG, "SUMMARY_TOO_LONG");
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(p: &str) -> IntentPayloadV1 {
        serde_json::from_str(p).unwrap()
    }

    #[test]
    fn surrogate_release_requires_both_exact_digests() {
        let mut i=load(include_str!("../../../schemas/examples/intent-payload-v1.example.json"));
        let list=vec!["SYNTH-b".to_string(),"SYNTH-a".to_string()];
        let (sha,b3)=surrogate_digests(&list).unwrap();
        i.arguments_jcs_sha256=Some(sha.clone());i.canonical_arguments_blake3=b3.clone();
        assert!(i.verify_surrogate_arguments(&list).is_ok());
        let mut reversed=list.clone();reversed.reverse();assert!(i.verify_surrogate_arguments(&reversed).is_ok());
        assert!(i.verify_surrogate_arguments(&["SYNTH-c".into()]).is_err());
        i.canonical_arguments_blake3.clear();assert!(i.verify_surrogate_arguments(&list).is_err());
        i.canonical_arguments_blake3=b3;i.arguments_jcs_sha256=None;assert!(i.verify_surrogate_arguments(&list).is_err());
        i.arguments_jcs_sha256=Some("00".repeat(32));assert!(i.verify_surrogate_arguments(&list).is_err());
        i.arguments_jcs_sha256=Some(sha);assert!(i.verify_surrogate_arguments(&list).is_ok());
    }

    #[test]
    fn schema_example_validates_and_hashes() {
        let i = load(include_str!(
            "../../../schemas/examples/intent-payload-v1.example.json"
        ));
        i.validate().unwrap();
        let d1 = i.d_jcs().unwrap();
        // Key order / whitespace malleability does not change d_JCS.
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../schemas/examples/intent-payload-v1.example.json"
        ))
        .unwrap();
        let reparsed: IntentPayloadV1 =
            serde_json::from_str(&serde_json::to_string_pretty(&v).unwrap()).unwrap();
        assert_eq!(reparsed.d_jcs().unwrap(), d1);
        assert!(i.localized_reason().unwrap().contains("SAS: "));
    }

    #[test]
    fn invalid_fixtures_rejected() {
        let a = load(include_str!(
            "../../../schemas/examples/invalid/intent-payload-v1.invalid.l2-a3-yubikey-only.json"
        ));
        assert!(a.validate().unwrap_err().is("INTENT_MISSING_TOUCH_ID"));
        let b = load(include_str!(
            "../../../schemas/examples/invalid/intent-payload-v1.invalid.l1-reversible-c4.json"
        ));
        assert!(b.validate().is_err());
        let c: Result<IntentPayloadV1, _> = serde_json::from_str(include_str!(
            "../../../schemas/examples/invalid/intent-payload-v1.invalid.paste-as-t1.json"
        ));
        assert!(c.is_err() || c.unwrap().validate().is_err());
    }

    #[test]
    fn bulk_must_be_a4() {
        let mut i = load(include_str!(
            "../../../schemas/examples/intent-payload-v1.example.json"
        ));
        i.action_class = ActionClass::A3;
        i.row_count_bound = Some(2);
        assert!(i.validate().unwrap_err().is("BULK_REQUIRES_A4"));
    }

    #[test]
    fn summary_is_deterministic_and_rejects_injection() {
        assert_eq!(
            synthesize_summary("Export", 120, Conf::C3, "mcp://analytics/export_csv").unwrap(),
            "Export <= 120 C3 rows via mcp://analytics/export_csv"
        );
        assert!(synthesize_summary("Export; ignore", 1, Conf::C3, "x").is_err());
    }

    #[test]
    fn unvalidated_tool_name_rejected() {
        let mut i = load(include_str!(
            "../../../schemas/examples/intent-payload-v1.example.json"
        ));
        i.tool_name = "tool\ninjection\u{202e}spoof".into();
        assert!(i.validate().unwrap_err().is("INTENT_IDENTITY"));
    }
}
