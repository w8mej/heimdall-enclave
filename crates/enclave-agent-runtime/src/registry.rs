//! Signed MCP tool registry (`enclave-mcp-lock.json`, FS-704 §4.2.3–§4.2.4,
//! GAP-04 / GAP-06).
//!
//! Every fact the PDP needs about a tool — action class, sink clearance,
//! namespace, root-mutation flag, which arguments are `AST_STRUCTURAL`,
//! where the row bound lives, the output label floor and which output fields
//! identify data subjects — comes from this lock, never from the caller.
//! `tools/list` pins are taken from it as well (no peer-settable pins).
//!
//! A tool absent from the lock is **default-conservative**: every argument is
//! `AST_STRUCTURAL` (rejecting all `T3` data), outputs are `(C3, T3)`, the
//! sink clearance is `C1` (nothing confidential may be written to it), the
//! action class is `A2`, and it has no row-bound argument.
//!
//! Distribution: the lock is a TUF target resolved through UID 702 (GAP-20,
//! Phase 2). Until then UID 704 loads it from `--mcp-lock-file` and records
//! its BLAKE3 in every decision receipt.

use std::collections::BTreeMap;

use enclave_core::error::EnclaveResult;
use enclave_core::label::{Conf, SlotKind};
use enclave_core::profile::ActionClass;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cedar_engine::ToolResource;
use crate::tools::{tools_list_digest, ToolPins};

/// One tool's signed metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSpec {
    /// Tool name as listed by the server (`tools/list`).
    pub name: String,
    /// Action class.
    pub action_class: ActionClass,
    /// Highest confidentiality the tool may receive.
    pub sink_clearance: Conf,
    /// Namespace the tool acts in.
    pub namespace: String,
    /// Mutates TUF roots / `pf` / policy.
    #[serde(default)]
    pub mutates_root: bool,
    /// Canonical verb for the trusted intent summary (`[A-Za-z]+`).
    pub canonical_verb: String,
    /// Slot kind per argument; unlisted arguments are `AST_STRUCTURAL`.
    #[serde(default)]
    pub slots: BTreeMap<String, SlotKind>,
    /// Integer argument that bounds returned rows (absent: 1 row).
    #[serde(default)]
    pub row_count_arg: Option<String>,
    /// Maximum value accepted for `row_count_arg`.
    #[serde(default = "one")]
    pub max_rows: u64,
    /// QIF charge per call (millibits), when the tool itself releases bits.
    #[serde(default)]
    pub qif_mb_per_call: i64,
    /// Output label floor.
    pub output_conf: Conf,
    /// JSON keys whose values identify data subjects in the output.
    #[serde(default)]
    pub entity_key_fields: Vec<String>,
}

fn one() -> u64 {
    1
}

/// One MCP server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSpec {
    /// Server id.
    pub server: String,
    /// `blake3(JCS(tools/list))` pin.
    pub tools_list_blake3: String,
    /// Tools.
    pub tools: Vec<ToolSpec>,
}

/// `enclave-mcp-lock.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpLockV1 {
    /// Always 1.
    pub v: u8,
    /// Servers.
    pub servers: Vec<ServerSpec>,
}

/// What the PDP needs about one call, resolved from the lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTool {
    /// Cedar resource.
    pub resource: ToolResource,
    /// Spec (default-conservative when unannotated).
    pub spec: ToolSpec,
    /// Whether the tool was found in the lock.
    pub annotated: bool,
}

/// The loaded registry.
#[derive(Debug, Clone, Default)]
pub struct ToolRegistry {
    servers: BTreeMap<String, ServerSpec>,
    pins: ToolPins,
    lock_blake3: String,
}

impl ToolRegistry {
    /// Parse and validate a lock file.
    pub fn load(bytes: &[u8]) -> EnclaveResult<Self> {
        let lock: McpLockV1 =
            serde_json::from_slice(bytes).map_err(|e| err!(EINVAL, "MCP_LOCK_PARSE", "{e}"))?;
        if lock.v != 1 {
            fail!(EINVAL, "MCP_LOCK_VERSION");
        }
        let mut r = Self {
            lock_blake3: blake3::hash(bytes).to_hex().to_string(),
            ..Self::default()
        };
        for s in lock.servers {
            r.pins.pin(&s.server, &s.tools_list_blake3)?;
            for t in &s.tools {
                if t.canonical_verb.is_empty()
                    || !t.canonical_verb.bytes().all(|b| b.is_ascii_alphabetic())
                {
                    fail!(EINVAL, "MCP_LOCK_VERB", "{}/{}", s.server, t.name);
                }
                if t.max_rows == 0 || (t.row_count_arg.is_none() && t.max_rows != 1) {
                    fail!(EINVAL, "MCP_LOCK_ROWS", "{}/{}", s.server, t.name);
                }
                if t.max_rows > 1 && t.action_class < ActionClass::A4 && t.output_conf >= Conf::C3 {
                    // FS-703 §3.1: any `> 1`-row export of confidential data is `A4`.
                    fail!(
                        EINVAL,
                        "MCP_LOCK_BULK_REQUIRES_A4",
                        "{}/{}",
                        s.server,
                        t.name
                    );
                }
            }
            if r.servers.insert(s.server.clone(), s).is_some() {
                fail!(EINVAL, "MCP_LOCK_DUPLICATE_SERVER");
            }
        }
        Ok(r)
    }

    /// An empty registry: every tool is default-conservative and no server
    /// is pinned (so tool outputs are refused until a lock is loaded).
    pub fn empty() -> Self {
        Self {
            lock_blake3: blake3::hash(b"").to_hex().to_string(),
            ..Self::default()
        }
    }

    /// BLAKE3 of the loaded lock file.
    pub fn lock_blake3(&self) -> &str {
        &self.lock_blake3
    }

    /// Verify a live `tools/list` against the lock's pin.
    pub fn verify_tools_list(&self, server: &str, tools_list: &Value) -> EnclaveResult<String> {
        self.pins.verify(server, tools_list)
    }

    /// Resolve `(server, tool)`; unknown tools get the conservative default.
    pub fn resolve(&self, server: &str, tool: &str) -> ResolvedTool {
        let uri = format!("mcp://{server}/{tool}");
        match self
            .servers
            .get(server)
            .and_then(|s| s.tools.iter().find(|t| t.name == tool))
        {
            Some(t) => ResolvedTool {
                resource: ToolResource {
                    name: uri,
                    action_class: t.action_class,
                    sink_clearance: t.sink_clearance,
                    namespace: t.namespace.clone(),
                    mutates_root: t.mutates_root,
                },
                spec: t.clone(),
                annotated: true,
            },
            None => {
                let spec = ToolSpec {
                    name: tool.to_owned(),
                    action_class: ActionClass::A4,
                    sink_clearance: Conf::C1,
                    namespace: format!("unannotated:{server}"),
                    mutates_root: true,
                    canonical_verb: "Invoke".into(),
                    slots: BTreeMap::new(),
                    row_count_arg: None,
                    max_rows: 1,
                    qif_mb_per_call: 0,
                    output_conf: Conf::C3,
                    entity_key_fields: vec![],
                };
                ResolvedTool {
                    resource: ToolResource {
                        name: uri,
                        action_class: spec.action_class,
                        sink_clearance: spec.sink_clearance,
                        namespace: spec.namespace.clone(),
                        mutates_root: true,
                    },
                    spec,
                    annotated: false,
                }
            }
        }
    }
}

impl ResolvedTool {
    /// Slot kind of an argument (unlisted ⇒ `AST_STRUCTURAL`).
    pub fn slot_kind(&self, arg: &str) -> SlotKind {
        self.spec
            .slots
            .get(arg)
            .copied()
            .unwrap_or(SlotKind::AstStructural)
    }

    /// Row bound computed from the canonical arguments.
    pub fn row_count(&self, args: &Value) -> EnclaveResult<u64> {
        let Some(k) = &self.spec.row_count_arg else {
            return Ok(1);
        };
        let n = args
            .get(k)
            .and_then(Value::as_u64)
            .ok_or_else(|| err!(EINVAL, "ROW_BOUND_ARG_MISSING", "{k}"))?;
        if n == 0 || n > self.spec.max_rows {
            fail!(
                EPERM,
                "ROW_BOUND_EXCEEDS_LOCK",
                "{k}={n} (max {})",
                self.spec.max_rows
            );
        }
        Ok(n)
    }

    /// Subject ids in a JSON output (`entity_key_fields`), deduplicated.
    pub fn entity_ids(&self, payload: &[u8]) -> Vec<String> {
        if self.spec.entity_key_fields.is_empty() {
            return vec![];
        }
        let Ok(v) = serde_json::from_slice::<Value>(payload) else {
            return vec![];
        };
        let mut out = Vec::new();
        collect(&v, &self.spec.entity_key_fields, &mut out);
        out.sort();
        out.dedup();
        out
    }
}

fn collect(v: &Value, keys: &[String], out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                if keys.iter().any(|w| w == k) {
                    match x {
                        Value::String(s) => out.push(format!("{k}:{s}")),
                        Value::Number(n) => out.push(format!("{k}:{n}")),
                        _ => {}
                    }
                }
                collect(x, keys, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|x| collect(x, keys, out)),
        _ => {}
    }
}

/// Digest helper re-exported for lock authors.
pub fn digest_tools_list(v: &Value) -> EnclaveResult<String> {
    tools_list_digest(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample_lock(tools_list: &Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "v": 1,
            "servers": [{
                "server": "postgres",
                "tools_list_blake3": digest_tools_list(tools_list).unwrap(),
                "tools": [{
                    "name": "select_bounded", "action_class": "A1", "sink_clearance": "C3", "namespace": "dev-billing",
                    "canonical_verb": "Select", "slots": {"table": "AST_STRUCTURAL", "where_value": "BOUND_LITERAL"},
                    "row_count_arg": "limit", "max_rows": 25, "output_conf": "C2", "entity_key_fields": ["customer_id"]
                }]
            }]
        }))
        .unwrap()
    }

    #[test]
    fn lock_drives_every_fact_and_unknown_tools_are_conservative() {
        let tl = serde_json::json!({"tools": [{"name": "select_bounded"}]});
        let r = ToolRegistry::load(&sample_lock(&tl)).unwrap();
        let t = r.resolve("postgres", "select_bounded");
        assert!(t.annotated);
        assert_eq!(
            (t.resource.action_class, t.resource.sink_clearance),
            (ActionClass::A1, Conf::C3)
        );
        assert_eq!(t.slot_kind("where_value"), SlotKind::BoundLiteral);
        assert_eq!(t.slot_kind("undeclared"), SlotKind::AstStructural);
        assert_eq!(t.row_count(&serde_json::json!({"limit": 10})).unwrap(), 10);
        assert!(t
            .row_count(&serde_json::json!({"limit": 26}))
            .unwrap_err()
            .is("ROW_BOUND_EXCEEDS_LOCK"));
        assert!(t
            .row_count(&serde_json::json!({}))
            .unwrap_err()
            .is("ROW_BOUND_ARG_MISSING"));
        assert_eq!(
            t.entity_ids(br#"[{"customer_id":"c1","x":1},{"customer_id":"c1"},{"customer_id":7}]"#),
            vec!["customer_id:7", "customer_id:c1"]
        );
        r.verify_tools_list("postgres", &tl).unwrap();
        assert!(r
            .verify_tools_list("evil", &tl)
            .unwrap_err()
            .is("TOOLS_SERVER_NOT_PINNED"));

        let u = r.resolve("postgres", "drop_everything");
        assert!(!u.annotated);
        assert_eq!(u.resource.action_class, ActionClass::A4);
        assert!(u.resource.mutates_root);
        assert_eq!(
            (
                u.resource.sink_clearance,
                u.spec.output_conf,
                u.slot_kind("any")
            ),
            (Conf::C1, Conf::C3, SlotKind::AstStructural)
        );
    }

    #[test]
    fn lock_rejects_bulk_confidential_below_a4() {
        let tl = serde_json::json!({"tools": []});
        let mut v: Value = serde_json::from_slice(&sample_lock(&tl)).unwrap();
        v["servers"][0]["tools"][0]["output_conf"] = "C4".into();
        assert!(ToolRegistry::load(&serde_json::to_vec(&v).unwrap())
            .unwrap_err()
            .is("MCP_LOCK_BULK_REQUIRES_A4"));
    }
}
