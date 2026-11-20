//! Closed content schema for a dedicated complete root filter reload.
//!
//! These bytes establish content shape only. They do not authorize PF mutation,
//! prove root-policy ownership, bind protected file originals, observe live PF,
//! establish a native transaction or grant a startup/readiness permit. A caller
//! must separately own and verify every such dependency.
#![allow(dead_code)] // Isolated source candidate; no production mutation caller.

pub(super) const LLM_FILE: &str = "/private/etc/pf.anchors/com.enterprise.llm.isolation";
pub(super) const CAS_FILE: &str = "/private/etc/pf.anchors/com.enterprise.cas.swarm";

/// Exactly the already-required root filter attachment order and both canonical
/// child loads. No include, macro, table, option, translation, queue, parent
/// anchor or arbitrary root-rule preservation is inferred from this image.
const ROOT_FILTER: &[u8] = b"# BEGIN MCPMAC PF RULES\n\
anchor \"com.enterprise.llm.isolation\"\n\
load anchor \"com.enterprise.llm.isolation\" from \"/private/etc/pf.anchors/com.enterprise.llm.isolation\"\n\
anchor \"com.enterprise.cas.swarm\"\n\
load anchor \"com.enterprise.cas.swarm\" from \"/private/etc/pf.anchors/com.enterprise.cas.swarm\"\n\
# END MCPMAC PF RULES\n";
const LLM_POLICY: &[u8] = include_bytes!("pf_policy_llm.pf");
const CAS_POLICY: &[u8] = include_bytes!("pf_policy_cas.pf");

pub(super) fn render_root_filter() -> &'static [u8] { ROOT_FILTER }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ContentRefusal { RootFilter, LlmPolicy, CasPolicy }

/// Borrow the exact accepted input buffers. This is deliberately neither an
/// authority token nor a file-owner wrapper; no checked/current/native accessor
/// exists. The restore owner must retain the corresponding original descriptors
/// and recheck them at command boundaries under its original finite endpoint.
pub(super) struct CanonicalFilterImage<'a> {
    root: &'a [u8], llm: &'a [u8], cas: &'a [u8],
}
impl<'a> CanonicalFilterImage<'a> {
    pub(super) fn require(root: &'a [u8], llm: &'a [u8], cas: &'a [u8])
        -> Result<Self, ContentRefusal> {
        if root != ROOT_FILTER { return Err(ContentRefusal::RootFilter); }
        if llm != LLM_POLICY { return Err(ContentRefusal::LlmPolicy); }
        if cas != CAS_POLICY { return Err(ContentRefusal::CasPolicy); }
        Ok(Self { root, llm, cas })
    }
    pub(super) fn root_bytes(&self) -> &'a [u8] { self.root }
    pub(super) fn llm_bytes(&self) -> &'a [u8] { self.llm }
    pub(super) fn cas_bytes(&self) -> &'a [u8] { self.cas }
}

#[cfg(test)]
#[path = "pf_restore_input_tests.rs"]
mod tests;
