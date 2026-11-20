//! FS-704 §3.2 `IfcEnvelopeV1` — the signed label of an opaque SSA capability
//! handle (`schemas/ifc-envelope-v1.schema.json`).

use serde::{Deserialize, Serialize};

use crate::error::EnclaveResult;
use crate::fail;
use crate::label::{Conf, Label, SlotKind, Taint};

/// Maximum entity-key fan-in (F-022). Larger sets fail with `E2BIG`, never truncate.
pub const MAX_ENTITY_FANIN: usize = 64;

/// Origin kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginKind {
    /// The `T1` directive.
    UserDirective,
    /// A `T3` attachment.
    UserAttachment,
    /// An MCP tool return (always `T3`).
    McpToolOutput,
    /// Signed TUF/Cedar material (`T0`).
    SignedPolicy,
    /// Output of a deterministic enclave sanitizer (`T2`).
    EnclaveVerified,
}

/// Origin block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    /// Kind.
    pub kind: OriginKind,
    /// Pinned `blake3(JCS(tools/list))` of the producing MCP server.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mcp_tools_list_blake3: Option<String>,
    /// Producing tool.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tool_name: Option<String>,
}

/// QIF pool selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QifPool {
    /// Charged per structured entity key.
    EntityKey,
    /// The single 24h pool for unstructured C3/C4 data.
    GlobalUnstructuredC3C424hPool,
}

/// Which HPKE tier seals the underlying surrogate (ADR-009).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VaultTier {
    /// Not vaulted.
    #[serde(rename = "none")]
    None,
    /// `Envelope_A3`.
    A3,
    /// `Envelope_A4`.
    A4,
}

/// `IfcEnvelopeV1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IfcEnvelopeV1 {
    /// Always 1.
    pub v: u8,
    /// `enclave.ifc.envelope.v1`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub schema_version: Option<String>,
    /// Boot epoch the handle was minted in.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub boot_epoch_id: Option<String>,
    /// `$v_<n>` or `$paste_<n>`.
    pub handle: String,
    /// BLAKE3 of the payload bytes.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub payload_blake3: Option<String>,
    /// Typed value descriptor.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub value_type: Option<String>,
    /// Label.
    pub label: Label,
    /// Vault tier.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub vault_tier: Option<VaultTier>,
    /// Entity keys `ek_<32 hex>`.
    pub entity_keys: Vec<String>,
    /// QIF pool.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub qif_pool: Option<QifPool>,
    /// Slot kind (default `AST_STRUCTURAL`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub slot_kind: Option<SlotKind>,
    /// Parent handles.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub provenance_parents: Option<Vec<String>>,
    /// Digest of the provenance DAG.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub provenance_dag_blake3: Option<String>,
    /// Allowed declassifiers.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub allowed_declassifiers: Option<Vec<String>>,
    /// Origin.
    pub origin: Origin,
    /// Per-boot keyed BLAKE3 MAC over the envelope (see [`IfcEnvelopeV1::mac_input`]).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub enclave_boot_mac: Option<String>,
}

fn is_hex(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn valid_handle(h: &str) -> bool {
    let rest = h.strip_prefix("$v_").or_else(|| h.strip_prefix("$paste_"));
    rest.is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Validate an entity key `ek_[0-9a-f]{32}`.
pub fn valid_entity_key(k: &str) -> bool {
    k.strip_prefix("ek_").is_some_and(|h| is_hex(h, 32))
}

impl IfcEnvelopeV1 {
    /// Enforce every schema rule plus the fail-closed semantic invariants.
    pub fn validate(&self) -> EnclaveResult<()> {
        if self.v != 1 {
            fail!(EINVAL, "BAD_VERSION");
        }
        if let Some(sv) = &self.schema_version {
            if sv != "enclave.ifc.envelope.v1" {
                fail!(EINVAL, "BAD_SCHEMA_VERSION");
            }
        }
        if let Some(b) = &self.boot_epoch_id {
            crate::seq::validate_epoch_id(b)?;
        }
        if !valid_handle(&self.handle) {
            fail!(
                EACCES,
                "HANDLE_FORGERY",
                "malformed handle {:?}",
                self.handle
            );
        }
        if self.entity_keys.len() > MAX_ENTITY_FANIN {
            fail!(
                E2BIG,
                "PROVENANCE_FANIN_EXCEEDED",
                "{} > {MAX_ENTITY_FANIN}",
                self.entity_keys.len()
            );
        }
        let mut seen = std::collections::HashSet::new();
        for k in &self.entity_keys {
            if !valid_entity_key(k) {
                fail!(EINVAL, "BAD_ENTITY_KEY");
            }
            if !seen.insert(k) {
                fail!(EINVAL, "DUPLICATE_ENTITY_KEY");
            }
        }
        if self.label.c >= Conf::C3 && self.entity_keys.is_empty() {
            fail!(
                EPERM,
                "EMPTY_ENTITY_SET",
                "C3/C4 handles require >= 1 entity key"
            );
        }
        if matches!(
            self.origin.kind,
            OriginKind::McpToolOutput | OriginKind::UserAttachment
        ) && self.label.t != Taint::T3
        {
            fail!(
                EPERM,
                "UNTRUSTED_ORIGIN_NOT_T3",
                "{:?} must be T3",
                self.origin.kind
            );
        }
        if self.label.c == Conf::C4 {
            if let Some(VaultTier::A3) = self.vault_tier {
                fail!(
                    EPERM,
                    "C4_UNDER_A3_ENVELOPE",
                    "C4 surrogates are sealed only under Envelope_A4"
                );
            }
        }
        for d in [
            &self.payload_blake3,
            &self.provenance_dag_blake3,
            &self.enclave_boot_mac,
        ]
        .into_iter()
        .flatten()
        {
            if !is_hex(d, 64) {
                fail!(EINVAL, "BAD_DIGEST");
            }
        }
        if let Some(t) = &self.origin.mcp_tools_list_blake3 {
            if !is_hex(t, 64) {
                fail!(EINVAL, "BAD_TOOLS_LIST_DIGEST");
            }
        }
        if let Some(p) = &self.provenance_parents {
            if p.len() > MAX_ENTITY_FANIN || !p.iter().all(|h| valid_handle(h)) {
                fail!(E2BIG, "PROVENANCE_PARENTS_INVALID");
            }
        }
        if let Some(d) = &self.allowed_declassifiers {
            if d.len() > 32 || d.iter().any(|x| x.len() > 128) {
                fail!(E2BIG, "TOO_MANY_DECLASSIFIERS");
            }
        }
        if let Some(vt) = &self.value_type {
            if vt.len() > 128 {
                fail!(EINVAL, "VALUE_TYPE_TOO_LONG");
            }
        }
        Ok(())
    }

    /// Effective slot kind (schema default `AST_STRUCTURAL`).
    pub fn slot(&self) -> SlotKind {
        self.slot_kind.unwrap_or(SlotKind::AstStructural)
    }

    /// Canonical bytes covered by `enclave_boot_mac` (JCS of the envelope minus the MAC field).
    pub fn mac_input(&self) -> EnclaveResult<Vec<u8>> {
        let mut c = self.clone();
        c.enclave_boot_mac = None;
        crate::jcs::to_jcs_bytes(&c)
    }

    /// Compute and set `enclave_boot_mac` under the per-boot SEP-seeded key.
    pub fn seal(&mut self, boot_key: &crate::secret::SecretKey32) -> EnclaveResult<()> {
        let m = boot_key.mac(&self.mac_input()?);
        self.enclave_boot_mac = Some(hex::encode(m));
        Ok(())
    }

    /// Verify the MAC; any mismatch (forged handle, downgraded taint) is
    /// `EACCES: HANDLE_FORGERY`.
    pub fn verify_mac(&self, boot_key: &crate::secret::SecretKey32) -> EnclaveResult<()> {
        self.validate()?;
        let Some(mac) = &self.enclave_boot_mac else {
            fail!(EACCES, "HANDLE_FORGERY", "missing MAC")
        };
        let want = hex::encode(boot_key.mac(&self.mac_input()?));
        if !crate::secret::ct_eq(want.as_bytes(), mac.as_bytes()) {
            fail!(EACCES, "HANDLE_FORGERY");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretKey32;

    fn example() -> IfcEnvelopeV1 {
        serde_json::from_str(include_str!(
            "../../../schemas/examples/ifc-envelope-v1.example.json"
        ))
        .unwrap()
    }

    #[test]
    fn schema_example_validates() {
        example().validate().unwrap();
    }

    #[test]
    fn invalid_fixtures_fail_closed() {
        let fanin: IfcEnvelopeV1 = serde_json::from_str(include_str!(
            "../../../schemas/examples/invalid/ifc-envelope-v1.invalid.fanin-65.json"
        ))
        .unwrap();
        assert!(fanin
            .validate()
            .unwrap_err()
            .is("PROVENANCE_FANIN_EXCEEDED"));
        let t1: IfcEnvelopeV1 = serde_json::from_str(include_str!(
            "../../../schemas/examples/invalid/ifc-envelope-v1.invalid.tool-output-t1.json"
        ))
        .unwrap();
        assert!(t1.validate().unwrap_err().is("UNTRUSTED_ORIGIN_NOT_T3"));
    }

    #[test]
    fn mac_detects_taint_downgrade_and_handle_forgery() {
        let k = SecretKey32::random();
        let mut e = example();
        e.seal(&k).unwrap();
        e.verify_mac(&k).unwrap();
        let mut down = e.clone();
        down.label.t = Taint::T2;
        down.origin.kind = OriginKind::EnclaveVerified;
        assert!(down.verify_mac(&k).unwrap_err().is("HANDLE_FORGERY"));
        let mut forged = e.clone();
        forged.handle = "$v_99".into();
        assert!(forged.verify_mac(&k).unwrap_err().is("HANDLE_FORGERY"));
        assert!(e.verify_mac(&SecretKey32::random()).is_err());
    }

    #[test]
    fn c3_requires_entity_keys_and_c4_never_a3() {
        let mut e = example();
        e.entity_keys.clear();
        assert!(e.validate().unwrap_err().is("EMPTY_ENTITY_SET"));
        let mut e = example();
        e.label.c = Conf::C4;
        e.vault_tier = Some(VaultTier::A3);
        assert!(e.validate().unwrap_err().is("C4_UNDER_A3_ENVELOPE"));
    }
}
