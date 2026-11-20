//! Native Rust Cedar PDP (ADR-008): the signed `.cedar` + `.cedarschema`
//! bundle is strictly validated once at load; per-call requests are built
//! from trusted, enclave-computed attributes only. The single latency budget
//! is `p99 <= 45 µs` for the end-to-end evaluation (`tests/cedar_slo.rs`).
//! Hot-swapped bundles come only from the TUF target UID 702 verifies; an
//! inline bundle must be byte-identical to it (`admit_inline_bundle`, DEFECT-F-64).

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityId, EntityTypeName, EntityUid,
    PolicySet, Request, RestrictedExpression, Schema, ValidationMode, Validator,
};
use enclave_core::error::EnclaveResult;
use enclave_core::label::{Conf, Label};
use enclave_core::profile::{ActionClass, Profile};
use enclave_core::{err, fail};

/// Target media type for the signed Cedar bundle (GAP-32).
pub const CEDAR_BUNDLE_MEDIA_TYPE: &str = "application/vnd.enclave.policy.cedar.v1";
/// Reserved target name for the policy bundle in TUF.
pub const CEDAR_BUNDLE_TARGET: &str = "enclave-policy.cedar.v1.json";

/// Embedded default schema.
pub const DEFAULT_SCHEMA: &str = include_str!("../policies/mcpmac.cedarschema");
/// Embedded deny-all default policies (bootstrap only, GAP-32).
pub const DEFAULT_POLICIES: &str =
    "// deny-all bootstrap (GAP-32)\nforbid (principal, action, resource);\n";
/// Embedded baseline policies.
pub const BASELINE_POLICIES: &str = include_str!("../policies/mcpmac.cedar");

/// The signed Cedar policy bundle containing schema and policies.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct CedarBundle {
    /// .cedarschema source text.
    pub schema: String,
    /// .cedar policy source text.
    pub policies: String,
}

impl CedarBundle {
    /// Create bundle from schema and policy strings.
    pub fn new(schema: impl Into<String>, policies: impl Into<String>) -> Self {
        Self {
            schema: schema.into(),
            policies: policies.into(),
        }
    }

    /// Baseline bundle with default schema and baseline policies.
    pub fn baseline() -> Self {
        Self::new(DEFAULT_SCHEMA, BASELINE_POLICIES)
    }

    /// Parse from JSON bytes.
    pub fn from_json_bytes(bytes: &[u8]) -> EnclaveResult<Self> {
        serde_json::from_slice(bytes).map_err(|e| err!(EINVAL, "CEDAR_BUNDLE_DECODE", "{e}"))
    }

    /// Serialize to canonical JSON bytes.
    pub fn to_json_bytes(&self) -> EnclaveResult<Vec<u8>> {
        serde_json::to_vec_pretty(self).map_err(|e| err!(EINVAL, "CEDAR_BUNDLE_ENCODE", "{e}"))
    }
}

/// Fetch and decode the signed Cedar policy bundle from UID 702 (SwarmSync).
pub fn fetch_cedar_bundle(socket_dir: &std::path::Path, dev: bool) -> EnclaveResult<CedarBundle> {
    let bytes = fetch_signed_bundle_bytes(Some(socket_dir), dev)?;
    CedarBundle::from_json_bytes(&bytes)
}

/// Raw bytes of the signed policy target as served (and TUF-verified) by UID 702.
/// No socket dir means no signed source: `Err`, which callers treat as "refuse".
pub fn fetch_signed_bundle_bytes(
    socket_dir: Option<&std::path::Path>,
    dev: bool,
) -> EnclaveResult<Vec<u8>> {
    let dir = socket_dir.ok_or_else(|| {
        err!(
            EINVAL,
            "POLICY_REFRESH",
            "no socket_dir configured to fetch the signed bundle"
        )
    })?;
    enclave_core::host_config::fetch_tuf_target(dir, CEDAR_BUNDLE_TARGET, dev)
}

/// Marker carried only by builds that can load an unsigned inline bundle
/// (DEFECT-F-64). `scripts/check-release-no-simulation.sh` asserts it is absent
/// from release binaries.
#[cfg(feature = "simulation")]
pub const UNSIGNED_INLINE_POLICY_MARKER: &str = "MCPMac unsigned inline policy (simulation)";

/// Where an installed policy bundle came from (journalled on every hot swap).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyProvenance {
    /// Fetched from UID 702 as the TUF-verified target.
    TufSigned,
    /// Supplied inline and byte-identical to the TUF-verified target.
    InlineMatchesSignedTarget,
    /// Supplied inline, unsigned; development simulation builds only.
    #[cfg(feature = "simulation")]
    InlineUnsignedDevSimulation,
}

impl PolicyProvenance {
    /// Journal spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TufSigned => "tuf_signed",
            Self::InlineMatchesSignedTarget => "inline_matches_signed_target",
            #[cfg(feature = "simulation")]
            Self::InlineUnsignedDevSimulation => "inline_unsigned_dev_simulation",
        }
    }

    /// Warning journalled next to the provenance (the unsigned dev path only).
    pub fn warning(self) -> Option<&'static str> {
        match self {
            Self::TufSigned | Self::InlineMatchesSignedTarget => None,
            #[cfg(feature = "simulation")]
            Self::InlineUnsignedDevSimulation => Some(UNSIGNED_INLINE_POLICY_MARKER),
        }
    }
}

/// DEFECT-F-64: decide whether an inline bundle may be installed.
///
/// `signed` is the outcome of fetching the TUF-verified target from UID 702.
/// The inline bytes are admitted only when byte-identical to it, and the
/// bundle is decoded from the *fetched* bytes. Anything else is refused with
/// `EPERM POLICY_INLINE_UNSIGNED`, except in a `simulation` build running in
/// same-UID development mode, where the unsigned bytes load with a distinct
/// provenance.
pub fn admit_inline_bundle(
    offered: &[u8],
    signed: EnclaveResult<Vec<u8>>,
    dev_same_uid: bool,
) -> EnclaveResult<(CedarBundle, PolicyProvenance)> {
    let refusal = match signed {
        Ok(signed) if signed.as_slice() == offered => {
            let bundle = CedarBundle::from_json_bytes(&signed)?;
            return Ok((bundle, PolicyProvenance::InlineMatchesSignedTarget));
        }
        Ok(signed) => format!(
            "inline bundle (blake3 {}) differs from the signed target {CEDAR_BUNDLE_TARGET} (blake3 {})",
            blake3::hash(offered).to_hex(),
            blake3::hash(&signed).to_hex()
        ),
        Err(e) => format!("signed target {CEDAR_BUNDLE_TARGET} unavailable: {e}"),
    };
    admit_unsigned(offered, dev_same_uid, refusal)
}

#[cfg(feature = "simulation")]
fn admit_unsigned(
    offered: &[u8],
    dev_same_uid: bool,
    refusal: String,
) -> EnclaveResult<(CedarBundle, PolicyProvenance)> {
    if !dev_same_uid {
        fail!(EPERM, "POLICY_INLINE_UNSIGNED", "{refusal}");
    }
    let bundle = CedarBundle::from_json_bytes(offered)?;
    Ok((bundle, PolicyProvenance::InlineUnsignedDevSimulation))
}

#[cfg(not(feature = "simulation"))]
fn admit_unsigned(
    _offered: &[u8],
    _dev_same_uid: bool,
    refusal: String,
) -> EnclaveResult<(CedarBundle, PolicyProvenance)> {
    fail!(EPERM, "POLICY_INLINE_UNSIGNED", "{refusal}")
}

/// Cedar actions MCPMac evaluates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CedarAction {
    /// `MCPMac::Action::"InvokeTool"`.
    InvokeTool,
    /// `MCPMac::Action::"DeclassifyEnum"`.
    DeclassifyEnum,
}

/// A tool resource description.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ToolResource {
    /// Tool URI.
    pub name: String,
    /// Action class.
    pub action_class: ActionClass,
    /// Sink clearance.
    pub sink_clearance: Conf,
    /// Namespace.
    pub namespace: String,
    /// Mutates TUF roots / `pf` / policy.
    pub mutates_root: bool,
}

/// Per-call context (all values computed by `_enclaveifc`, never by the caller).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallFacts {
    /// Joined input label.
    pub input: Label,
    /// Highest taint in AST-structural slots (rank).
    pub ast_taint: u8,
    /// Requested rows.
    pub row_count: u64,
    /// QIF charge.
    pub qif_mb: i64,
    /// Effective profile.
    pub profile: Profile,
    /// A verified Track-4 hardware intent grant is attached.
    pub hw_grant: bool,
    /// Requested namespace.
    pub target_namespace: String,
}

/// Maximum retained entity pairs (DEFECT-F-70).
pub const ENTITY_CACHE_CAPACITY: usize = 128;
/// Maximum total UTF-8 bytes in a cache key. Oversized keys are evaluated uncached.
pub const ENTITY_CACHE_KEY_BYTES: usize = 1024;

type EntityCacheKey = (String, u32, ToolResource);

#[derive(Debug, Default)]
struct EntityCache {
    entries: HashMap<EntityCacheKey, Entities>,
    order: VecDeque<EntityCacheKey>,
}

impl EntityCache {
    fn cacheable(key: &EntityCacheKey) -> bool {
        key.0
            .len()
            .saturating_add(key.2.name.len())
            .saturating_add(key.2.namespace.len())
            <= ENTITY_CACHE_KEY_BYTES
    }

    fn get(&mut self, key: &EntityCacheKey) -> Option<Entities> {
        let value = self.entries.get(key)?.clone();
        self.order.retain(|k| k != key);
        self.order.push_back(key.clone());
        Some(value)
    }

    fn insert(&mut self, key: EntityCacheKey, value: Entities) {
        if !Self::cacheable(&key) {
            return;
        }
        self.order.retain(|k| k != &key);
        if !self.entries.contains_key(&key) && self.entries.len() >= ENTITY_CACHE_CAPACITY {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        self.order.push_back(key.clone());
        self.entries.insert(key, value);
    }
}

/// The loaded, validated policy engine.
#[derive(Debug)]
pub struct CedarEngine {
    schema: Schema,
    policies: PolicySet,
    authorizer: Authorizer,
    bundle_blake3: [u8; 32],
    // Pre-parsed names: the hot path never invokes the Cedar parser.
    agent_type: EntityTypeName,
    tool_type: EntityTypeName,
    invoke_uid: EntityUid,
    declassify_uid: EntityUid,
    /// Pre-built entities cache per (agent, depth, tool) (GAP-22).
    entities_cache: std::sync::RwLock<EntityCache>,
}

impl CedarEngine {
    /// Load and strictly validate a bundle. Any parse or validation error fails closed.
    pub fn load(schema_src: &str, policy_src: &str) -> EnclaveResult<Self> {
        let (schema, _warnings) = Schema::from_cedarschema_str(schema_src)
            .map_err(|e| err!(EINVAL, "CEDAR_SCHEMA", "{e}"))?;
        let policies = PolicySet::from_str(policy_src)
            .map_err(|e| err!(EINVAL, "CEDAR_POLICY_PARSE", "{e}"))?;
        let v = Validator::new(schema.clone()).validate(&policies, ValidationMode::Strict);
        if !v.validation_passed() {
            let errs: Vec<String> = v.validation_errors().map(|e| e.to_string()).collect();
            fail!(EINVAL, "CEDAR_VALIDATION", "{}", errs.join("; "));
        }
        let mut h = blake3::Hasher::new();
        h.update(b"MCPMac-CedarBundle-v1\0");
        h.update(&(schema_src.len() as u64).to_be_bytes());
        h.update(schema_src.as_bytes());
        h.update(policy_src.as_bytes());
        let ty =
            |n: &str| EntityTypeName::from_str(n).map_err(|e| err!(EINVAL, "CEDAR_UID", "{e}"));
        Ok(Self {
            schema,
            policies,
            authorizer: Authorizer::new(),
            bundle_blake3: *h.finalize().as_bytes(),
            agent_type: ty("MCPMac::Agent")?,
            tool_type: ty("MCPMac::Tool")?,
            invoke_uid: Self::uid(r#"MCPMac::Action::"InvokeTool""#)?,
            declassify_uid: Self::uid(r#"MCPMac::Action::"DeclassifyEnum""#)?,
            entities_cache: std::sync::RwLock::new(EntityCache::default()),
        })
    }

    /// Load and strictly validate from a bundle.
    pub fn from_bundle(bundle: &CedarBundle) -> EnclaveResult<Self> {
        Self::load(&bundle.schema, &bundle.policies)
    }

    /// The baseline bundle (permissive baseline, used for tests and initial provisioning).
    pub fn baseline_bundle() -> EnclaveResult<Self> {
        Self::load(DEFAULT_SCHEMA, BASELINE_POLICIES)
    }

    /// The embedded default bundle (deny-all bootstrap, GAP-32).
    pub fn default_bundle() -> EnclaveResult<Self> {
        Self::load(DEFAULT_SCHEMA, DEFAULT_POLICIES)
    }

    /// `policy_bundle_blake3` (bound into Biscuit authority blocks and intents).
    pub fn bundle_blake3(&self) -> [u8; 32] {
        self.bundle_blake3
    }

    /// The schema (for tests that validate requests strictly).
    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    fn uid(s: &str) -> EnclaveResult<EntityUid> {
        EntityUid::from_str(s).map_err(|e| err!(EINVAL, "CEDAR_UID", "{e}"))
    }

    fn quote(s: &str) -> String {
        // Cedar entity ids are string literals; escape quotes/backslashes.
        s.replace('\\', "\\\\").replace('"', "\\\"")
    }

    /// Build the request + entities for a tool call.
    pub fn build(
        &self,
        agent: &str,
        depth: u32,
        action: CedarAction,
        tool: &ToolResource,
        f: &CallFacts,
        validate: bool,
    ) -> EnclaveResult<(Request, Entities)> {
        // Entity ids are opaque strings (no escaping needed when constructed
        // directly rather than parsed).
        let p = EntityUid::from_type_name_and_id(self.agent_type.clone(), EntityId::new(agent));
        let a = match action {
            CedarAction::InvokeTool => self.invoke_uid.clone(),
            CedarAction::DeclassifyEnum => self.declassify_uid.clone(),
        };
        let r = EntityUid::from_type_name_and_id(self.tool_type.clone(), EntityId::new(&tool.name));
        let cache_key = (agent.to_owned(), depth, tool.clone());
        let cached = {
            let mut guard = self
                .entities_cache
                .write()
                .map_err(|_| err!(EIO, "CEDAR_CACHE_POISONED"))?;
            guard.get(&cache_key)
        };
        let ents = match cached {
            Some(e) => e,
            None => {
                let pa = HashMap::from([
                    (
                        "depth".to_owned(),
                        RestrictedExpression::new_long(depth as i64),
                    ),
                    (
                        "role".to_owned(),
                        RestrictedExpression::new_string(agent.to_owned()),
                    ),
                ]);
                let ra = HashMap::from([
                    (
                        "action_class".to_owned(),
                        RestrictedExpression::new_long(tool.action_class as i64),
                    ),
                    (
                        "sink_clearance".to_owned(),
                        RestrictedExpression::new_long(tool.sink_clearance.rank() as i64),
                    ),
                    (
                        "namespace".to_owned(),
                        RestrictedExpression::new_string(tool.namespace.clone()),
                    ),
                    (
                        "mutates_root".to_owned(),
                        RestrictedExpression::new_bool(tool.mutates_root),
                    ),
                ]);
                let pe = Entity::new(p.clone(), pa, HashSet::new())
                    .map_err(|e| err!(EINVAL, "CEDAR_ENTITY", "{e}"))?;
                let re = Entity::new(r.clone(), ra, HashSet::new())
                    .map_err(|e| err!(EINVAL, "CEDAR_ENTITY", "{e}"))?;
                let schema = validate.then_some(&self.schema);
                let computed = Entities::from_entities([pe, re], schema)
                    .map_err(|e| err!(EINVAL, "CEDAR_ENTITIES", "{e}"))?;
                self.entities_cache
                    .write()
                    .map_err(|_| err!(EIO, "CEDAR_CACHE_POISONED"))?
                    .insert(cache_key, computed.clone());
                computed
            }
        };
        let ctx = Context::from_pairs([
            (
                "input_c".to_owned(),
                RestrictedExpression::new_long(f.input.c.rank() as i64),
            ),
            (
                "input_t".to_owned(),
                RestrictedExpression::new_long(f.input.t.rank() as i64),
            ),
            (
                "ast_taint".to_owned(),
                RestrictedExpression::new_long(f.ast_taint as i64),
            ),
            (
                "row_count".to_owned(),
                RestrictedExpression::new_long(
                    i64::try_from(f.row_count).map_err(|_| err!(EINVAL, "ROWS"))?,
                ),
            ),
            (
                "qif_mb".to_owned(),
                RestrictedExpression::new_long(f.qif_mb),
            ),
            (
                "profile".to_owned(),
                RestrictedExpression::new_long(f.profile.number() as i64),
            ),
            (
                "hw_grant".to_owned(),
                RestrictedExpression::new_bool(f.hw_grant),
            ),
            (
                "target_namespace".to_owned(),
                RestrictedExpression::new_string(f.target_namespace.clone()),
            ),
        ])
        .map_err(|e| err!(EINVAL, "CEDAR_CONTEXT", "{e}"))?;
        let schema = validate.then_some(&self.schema);
        let req =
            Request::new(p, a, r, ctx, schema).map_err(|e| err!(EINVAL, "CEDAR_REQUEST", "{e}"))?;
        Ok((req, ents))
    }

    /// Evaluate. Returns `(allowed, determining policy ids)`.
    pub fn is_authorized(
        &self,
        agent: &str,
        depth: u32,
        action: CedarAction,
        tool: &ToolResource,
        f: &CallFacts,
    ) -> EnclaveResult<(bool, Vec<String>)> {
        let (req, ents) = self.build(agent, depth, action, tool, f, false)?;
        let resp = self.authorizer.is_authorized(&req, &self.policies, &ents);
        if resp.diagnostics().errors().next().is_some() {
            // An evaluation error is never an allow.
            return Ok((false, vec!["EVALUATION_ERROR".into()]));
        }
        let reasons = resp
            .diagnostics()
            .reason()
            .map(|p| {
                self.policies
                    .policy(p)
                    .and_then(|x| x.annotation("id").map(str::to_owned))
                    .unwrap_or_else(|| p.to_string())
            })
            .collect();
        Ok((resp.decision() == Decision::Allow, reasons))
    }

    /// Static authorization check for plans before execution (GAP-18).
    ///
    /// A necessary condition only: the tool is the lock's resource and the
    /// profile is the active one, with the most favourable data facts a plan
    /// could present (directive-level input `C1/T1`, no hardware grant). A
    /// tool Cedar denies even then is refused before evaluation. It says
    /// nothing about the data a plan passes; that is decided per call by
    /// `Pdp::authorize` (DEFECT-F-65).
    pub fn authorize_static(&self, agent: &str, tool: &ToolResource, profile: Profile) -> bool {
        self.plan_eligible(agent, 0, tool, profile, false)
    }

    /// Effect-free eligibility using the turn's verified principal and one
    /// policy snapshot. Hardware is hypothetical only when step-up was selected
    /// and the tool is A3/A4; real per-call authorization must obtain a grant.
    /// Fixed C1/T1, one-row and zero-charge facts can conservatively reject a
    /// call that a nonmonotonic custom policy would allow for other data.
    pub(crate) fn plan_eligible(&self, agent: &str, depth: u32, tool: &ToolResource,
        profile: Profile, step_up: bool) -> bool {
        let f = CallFacts {
            input: enclave_core::label::Label::DIRECTIVE,
            ast_taint: enclave_core::label::Taint::T1.rank(),
            row_count: 1,
            qif_mb: 0,
            profile,
            hw_grant: step_up && tool.action_class >= ActionClass::A3,
            target_namespace: tool.namespace.clone(),
        };
        match self.is_authorized(agent, depth, CedarAction::InvokeTool, tool, &f) {
            Ok((allow, _)) => allow,
            Err(_) => false,
        }
    }

    /// `Custody::ReversibleTokenize` decision for a named workflow.
    /// Only workflows the signed policy names are ever granted (GAP-05).
    pub fn reversible_tokenize(
        &self,
        agent: &str,
        workflow: &str,
        profile: Profile,
    ) -> EnclaveResult<bool> {
        let p = Self::uid(&format!(r#"MCPMac::Agent::"{}""#, Self::quote(agent)))?;
        let a = Self::uid(r#"Custody::Action::"ReversibleTokenize""#)?;
        let r = Self::uid(&format!(
            r#"Custody::Workflow::"{}""#,
            Self::quote(workflow)
        ))?;
        let pe = Entity::new(
            p.clone(),
            HashMap::from([
                ("depth".to_owned(), RestrictedExpression::new_long(0)),
                (
                    "role".to_owned(),
                    RestrictedExpression::new_string(agent.to_owned()),
                ),
            ]),
            HashSet::new(),
        )
        .map_err(|e| err!(EINVAL, "CEDAR_ENTITY", "{e}"))?;
        let re = Entity::new(r.clone(), HashMap::new(), HashSet::new())
            .map_err(|e| err!(EINVAL, "CEDAR_ENTITY", "{e}"))?;
        let ctx = Context::from_pairs([(
            "profile".to_owned(),
            RestrictedExpression::new_long(profile.number() as i64),
        )])
        .map_err(|e| err!(EINVAL, "CEDAR_CONTEXT", "{e}"))?;
        let req = Request::new(p, a, r, ctx, Some(&self.schema))
            .map_err(|e| err!(EINVAL, "CEDAR_REQUEST", "{e}"))?;
        let ents = Entities::from_entities([pe, re], Some(&self.schema))
            .map_err(|e| err!(EINVAL, "CEDAR_ENTITIES", "{e}"))?;
        Ok(self
            .authorizer
            .is_authorized(&req, &self.policies, &ents)
            .decision()
            == Decision::Allow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclave_core::label::Taint;

    fn tool(ac: ActionClass, sink: Conf) -> ToolResource {
        ToolResource {
            name: "mcp://postgres/select_bounded".into(),
            action_class: ac,
            sink_clearance: sink,
            namespace: "dev-billing".into(),
            mutates_root: false,
        }
    }

    fn facts(c: Conf, t: Taint, ast: u8) -> CallFacts {
        CallFacts {
            input: Label::new(c, t),
            ast_taint: ast,
            row_count: 1,
            qif_mb: 0,
            profile: Profile::L2,
            hw_grant: false,
            target_namespace: "dev-billing".into(),
        }
    }

    #[test]
    fn bundle_validates_strictly() {
        let e = CedarEngine::default_bundle().unwrap();
        assert_ne!(e.bundle_blake3(), [0u8; 32]);
        assert!(CedarEngine::load(
            DEFAULT_SCHEMA,
            "permit(principal, action == MCPMac::Action::\"Nope\", resource);"
        )
        .is_err());
        // Request built with schema validation conforms.
        e.build(
            "orchestrator",
            0,
            CedarAction::InvokeTool,
            &tool(ActionClass::A1, Conf::C3),
            &facts(Conf::C2, Taint::T1, 1),
            true,
        )
        .unwrap();
    }

    #[test]
    fn default_bundle_is_deny_all_bootstrap() {
        let e = CedarEngine::default_bundle().unwrap();
        assert_ne!(e.bundle_blake3(), [0u8; 32]);
        let (allow, _) = e
            .is_authorized(
                "orchestrator",
                0,
                CedarAction::InvokeTool,
                &tool(ActionClass::A1, Conf::C3),
                &facts(Conf::C2, Taint::T1, 1),
            )
            .unwrap();
        assert!(!allow, "default bundle must deny all actions fail-closed");
    }

    #[test]
    fn label_rules() {
        let e = CedarEngine::baseline_bundle().unwrap();
        let ok = |t: &ToolResource, f: &CallFacts| {
            e.is_authorized("orchestrator", 0, CedarAction::InvokeTool, t, f)
                .unwrap()
                .0
        };
        assert!(ok(
            &tool(ActionClass::A1, Conf::C3),
            &facts(Conf::C2, Taint::T1, 1)
        ));
        assert!(
            !ok(
                &tool(ActionClass::A1, Conf::C2),
                &facts(Conf::C3, Taint::T1, 1)
            ),
            "no write-down"
        );
        assert!(
            !ok(
                &tool(ActionClass::A1, Conf::C4),
                &facts(Conf::C2, Taint::T3, 3)
            ),
            "Biba"
        );
        assert!(
            !ok(
                &tool(ActionClass::A3, Conf::C4),
                &facts(Conf::C2, Taint::T1, 1)
            ),
            "A3 needs hw grant"
        );
        let mut f = facts(Conf::C2, Taint::T1, 1);
        f.hw_grant = true;
        assert!(ok(&tool(ActionClass::A3, Conf::C4), &f));
        let mut f = facts(Conf::C3, Taint::T1, 1);
        f.row_count = 2;
        assert!(
            !ok(&tool(ActionClass::A3, Conf::C4), &f),
            "bulk C3 requires A4"
        );
        f.target_namespace = "prod".into();
        assert!(!ok(&tool(ActionClass::A1, Conf::C4), &f));
        assert!(
            !e.is_authorized(
                "orchestrator",
                5,
                CedarAction::InvokeTool,
                &tool(ActionClass::A1, Conf::C3),
                &facts(Conf::C1, Taint::T1, 0)
            )
            .unwrap()
            .0
        );
    }

    #[test]
    fn custody_reversible_tokenize() {
        // The default bundle names no workflow: nothing is ever granted.
        let d = CedarEngine::default_bundle().unwrap();
        assert!(!d
            .reversible_tokenize("orchestrator", "fraud-review", Profile::L2)
            .unwrap());
        // An organisation bundle that names `fraud-review` grants only it, only in L2+.
        let org = format!(
            "{BASELINE_POLICIES}\n@id(\"wf\")\npermit (principal, action == Custody::Action::\"ReversibleTokenize\", resource == Custody::Workflow::\"fraud-review\") when {{ context.profile >= 2 }};\n"
        );
        let e = CedarEngine::load(DEFAULT_SCHEMA, &org).unwrap();
        assert!(e
            .reversible_tokenize("orchestrator", "fraud-review", Profile::L2)
            .unwrap());
        assert!(!e
            .reversible_tokenize("orchestrator", "fraud-review", Profile::L1)
            .unwrap());
        assert!(!e
            .reversible_tokenize("orchestrator", "adhoc", Profile::L3)
            .unwrap());
    }
}

#[cfg(test)]
mod f70_tests {
    use super::*;
    fn key(n: usize) -> EntityCacheKey {
        (
            "unverified".into(),
            0,
            ToolResource {
                name: format!("mcp://unknown/{n}"),
                action_class: ActionClass::A1,
                sink_clearance: Conf::C1,
                namespace: "unknown".into(),
                mutates_root: false,
            },
        )
    }
    #[test]
    fn f70_lru_keeps_hot_entries_and_bounds_both_collections() {
        let mut cache = EntityCache::default();
        for n in 0..ENTITY_CACHE_CAPACITY {
            cache.insert(key(n), Entities::empty());
        }
        assert!(cache.get(&key(0)).is_some());
        cache.insert(key(ENTITY_CACHE_CAPACITY), Entities::empty());
        assert!(cache.get(&key(0)).is_some());
        assert!(cache.get(&key(1)).is_none());
        assert_eq!(cache.entries.len(), ENTITY_CACHE_CAPACITY);
        assert_eq!(cache.order.len(), ENTITY_CACHE_CAPACITY);
        for _ in 0..1000 {
            cache.insert(key(0), Entities::empty());
        }
        assert_eq!(cache.order.len(), ENTITY_CACHE_CAPACITY);
        let mut big = key(0);
        big.2.name = "x".repeat(ENTITY_CACHE_KEY_BYTES + 1);
        cache.insert(big.clone(), Entities::empty());
        assert!(cache.get(&big).is_none());
    }
    #[test]
    fn f70_distinct_authorizations_do_not_accumulate_entities() {
        let engine = CedarEngine::baseline_bundle().unwrap();
        let f = CallFacts {
            input: Label::BOTTOM,
            ast_taint: 0,
            row_count: 1,
            qif_mb: 0,
            profile: Profile::L2,
            hw_grant: false,
            target_namespace: "unknown".into(),
        };
        for n in 0..10_000 {
            let (agent, depth, tool) = key(n);
            let (allow, _) = engine
                .is_authorized(&agent, depth, CedarAction::InvokeTool, &tool, &f)
                .unwrap();
            assert!(allow, "valid A1 functionality must survive eviction");
        }
        let cache = engine.entities_cache.read().unwrap();
        assert_eq!(cache.entries.len(), ENTITY_CACHE_CAPACITY);
        assert_eq!(cache.order.len(), ENTITY_CACHE_CAPACITY);
    }
    #[test]
    #[ignore = "one-million-call memory stress; run explicitly for DEFECT-F-70"]
    fn f70_one_million_distinct_authorizations_memory_stress() {
        let engine = CedarEngine::baseline_bundle().unwrap();
        let f = CallFacts {
            input: Label::BOTTOM,
            ast_taint: 0,
            row_count: 1,
            qif_mb: 0,
            profile: Profile::L2,
            hw_grant: false,
            target_namespace: "unknown".into(),
        };
        let before = enclave_core::resource::current_rss_bytes();
        for n in 0..1_000_000 {
            let (agent, depth, tool) = key(n);
            assert!(
                engine
                    .is_authorized(&agent, depth, CedarAction::InvokeTool, &tool, &f)
                    .unwrap()
                    .0
            );
        }
        let after = enclave_core::resource::current_rss_bytes();
        eprintln!(
            "F70 rss before={before:?} after={after:?} entries={}",
            engine.entities_cache.read().unwrap().entries.len()
        );
        assert_eq!(
            engine.entities_cache.read().unwrap().entries.len(),
            ENTITY_CACHE_CAPACITY
        );
        if let (Some(before), Some(after)) = (before, after) {
            assert!(
                after.saturating_sub(before) < 16 * 1024 * 1024,
                "cache RSS growth exceeds 16 MiB"
            );
        }
    }
}
