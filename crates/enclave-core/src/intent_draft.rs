//! `IntentDraftV1` (GAP-04 / GAP-09): the structured facts UID 704 derives
//! for a hardware step-up. UID 703 — never the caller — turns a draft into
//! the RFC 8785 `IntentPayloadV1`: it synthesises `human_summary_trusted`
//! from these fields, fills `required_factors` from the FS-703 matrix,
//! stamps its own clock, runs the chained ceremony and returns `d_JCS`.
//! No free-form text crosses this boundary.

use serde::{Deserialize, Serialize};

use crate::label::Conf;
use crate::profile::{ActionClass, Profile};

/// Step-up request built by UID 704 from its canonical tool-call request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentDraftV1 {
    /// Action class of the tool (from the signed MCP lock).
    pub action_class: ActionClass,
    /// Effective profile.
    pub profile: Profile,
    /// Joined confidentiality of the inputs.
    pub data_class: Conf,
    /// Tool URI.
    pub tool_name: String,
    /// Namespace.
    pub target_namespace: String,
    /// Canonical verb from the signed MCP lock (`[A-Za-z]+`, e.g. `Export`).
    pub canonical_verb: String,
    /// Rows the call may return (enforced as a hard truncator).
    pub row_count_bound: u64,
    /// SHA-256 of the JCS arguments (hex).
    pub arguments_jcs_sha256: String,
    /// BLAKE3 of the JCS arguments (hex).
    pub canonical_arguments_blake3: String,
    /// Policy bundle digest (hex).
    pub policy_blake3: String,
    /// QIF delta of the call (millibits).
    pub qif_millibits_delta: i64,
    /// TUF root / `pf` / policy mutation (adds the `k`-of-`n` quorum factor).
    pub org_root_mutation: bool,
}

/// Namespaces classified as organization root mutations (FS-703 §3.1, ADR-013).
pub const ORG_ROOT_NAMESPACES: &[&str] = &["tuf", "pf", "policy", "root", "enclave-admin"];

/// Tool URI prefixes classified as organization root mutations.
pub const ORG_ROOT_TOOL_PREFIXES: &[&str] = &["mcp://tuf/", "mcp://pf/", "mcp://policy/"];

/// Determine whether a tool invocation mutates organization root state.
pub fn is_org_root_mutation(tool_name: &str, target_namespace: Option<&str>) -> bool {
    if let Some(ns) = target_namespace {
        let ns_clean = ns.trim();
        for &root_ns in ORG_ROOT_NAMESPACES {
            if ns_clean == root_ns
                || ns_clean.starts_with(&format!("{root_ns}:"))
                || ns_clean.starts_with(&format!("{root_ns}/"))
                || ns_clean.starts_with(&format!("{root_ns}."))
            {
                return true;
            }
        }
    }
    for &prefix in ORG_ROOT_TOOL_PREFIXES {
        if tool_name.starts_with(prefix) {
            return true;
        }
    }
    false
}
