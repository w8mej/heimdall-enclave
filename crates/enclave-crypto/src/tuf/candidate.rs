//! Bounded, diagnostic verification of complete candidate-4 TUF child files.
//!
//! Inputs must come from a separately validated approved intent and an
//! independently pinned current client. This function verifies no approval,
//! custodian, factor, freshness certificate, signer isolation or publication.
//! It mutates no trusted state and returns no authorization or signing output.
//! Ordinary production TUF admission and root rotation remain separate APIs.

use super::*;
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};

/// Maximum exact attachment size, including every outer signature.
pub const MAX_CHILD_BYTES: usize = 1024 * 1024;
const MAX_DEPTH: usize = 64;
const MAX_NODES: usize = 65_536;
const MAX_SIGNATURES: usize = 64;

/// Complete-file commitment from a separately authenticated candidate intent.
/// Constructing this public diagnostic input does not authenticate that intent.
#[derive(Debug, Clone)]
pub struct ExpectedChild {
    /// Only literal top-level `targets` or `snapshot` are supported here.
    pub role: Role,
    /// Exact positive metadata version.
    pub version: u64,
    /// Exact complete file length, including the signatures array.
    pub length: u64,
    /// SHA256 of the exact complete file, never only its signed member.
    pub sha256: [u8; 32],
}

/// Diagnostic facts about exact bytes; this is not an approval or capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildFacts {
    /// Literal verified child role.
    pub role: Role,
    /// Exact verified child version.
    pub version: u64,
    /// Exact complete file length.
    pub length: u64,
    /// SHA256 of the exact complete file.
    pub sha256: [u8; 32],
    /// SHA256 of OLPC canonical signed-member bytes, retaining all fields.
    pub signed_body_sha256: [u8; 32],
    /// Version of the independently pinned client's current root.
    pub root_version: u64,
    /// Earlier exclusive expiry of the current root and this role.
    pub valid_until_unix: i64,
    /// Number of distinct authorized valid signatures supplied in sorted order.
    pub signatures: usize,
}

/// Exact parent commitment extracted from an independently approved, closed
/// intent. Constructing this diagnostic input does not authenticate that intent.
#[derive(Debug, Clone)]
pub struct ExpectedParent {
    /// Only snapshot or timestamp parent bodies are supported.
    pub role: Role,
    /// Exact currently adopted parent version, zero when no parent is adopted.
    pub base_version: u64,
    /// Strictly newer proposed parent version.
    pub new_version: u64,
    /// Exact OLPC canonical signed-member byte length, without an outer envelope.
    pub signed_body_bytes: u64,
    /// SHA256 of those exact signed-member bytes.
    pub signed_body_sha256: [u8; 32],
    /// Exact exclusive signed expiry in UTC milliseconds.
    pub expires_utc_ms: u64,
    /// Complete child-envelope commitment from that same approved intent.
    pub linked_child: ExpectedChild,
}

/// Parent/body/link diagnostics only; no signature, approval or adoption output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentFacts {
    /// Literal verified proposed parent role.
    pub role: Role,
    /// Exact proposed parent version.
    pub version: u64,
    /// Exact OLPC signed-member length.
    pub signed_body_bytes: u64,
    /// SHA256 of the complete canonical signed member.
    pub signed_body_sha256: [u8; 32],
    /// Exact parent expiry committed by the approved intent.
    pub expires_utc_ms: u64,
    /// Earliest exclusive parent, child or pinned current root expiry.
    pub valid_until_unix: i64,
    /// Facts about the one exact complete, genuinely signed child envelope.
    pub child: ChildFacts,
}

struct ValueSeed<'a> {
    depth: usize,
    remaining: &'a mut usize,
}
impl<'de> DeserializeSeed<'de> for ValueSeed<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        if self.depth > MAX_DEPTH || *self.remaining == 0 {
            return Err(serde::de::Error::custom("candidate JSON complexity bound"));
        }
        *self.remaining -= 1;
        deserializer.deserialize_any(ValueVisitor {
            depth: self.depth,
            remaining: self.remaining,
        })
    }
}
struct ValueVisitor<'a> {
    depth: usize,
    remaining: &'a mut usize,
}
impl<'de> Visitor<'de> for ValueVisitor<'_> {
    type Value = Value;
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("bounded duplicate-free integer JSON")
    }
    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Value, E> {
        Err(E::custom("OLPC floats forbidden"))
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.into()))
    }
    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(ValueSeed {
            depth: self.depth + 1,
            remaining: &mut *self.remaining,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut entries: A) -> Result<Value, A::Error> {
        let mut values = serde_json::Map::new();
        while let Some(key) = entries.next_key::<String>()? {
            // Reject decoded duplicate names BEFORE the corresponding value is
            // read or any map insertion can discard the earlier signed member.
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom("duplicate JSON member"));
            }
            let value = entries.next_value_seed(ValueSeed {
                depth: self.depth + 1,
                remaining: &mut *self.remaining,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
// serde_json's workspace arbitrary_precision feature can route a floating
// numeric token through visit_map rather than visit_f64. Reject non-integer or
// out-of-range numeric TOKENS before that feature-dependent visitor dispatch.
// Quoted bytes are never interpreted or rewritten; the real JSON parser still
// validates all escapes, separators and recursive object structure afterward.
fn integer_tokens(bytes: &[u8]) -> EnclaveResult<()> {
    let mut offset = 0;
    let mut quoted = false;
    while offset < bytes.len() {
        match bytes[offset] {
            b'\\' if quoted => {
                offset += 2;
                continue;
            }
            b'"' => quoted = !quoted,
            byte if !quoted && (byte == b'-' || byte.is_ascii_digit()) => {
                let start = offset;
                offset += 1;
                while offset < bytes.len()
                    && (bytes[offset].is_ascii_digit() || b".-+eE".contains(&bytes[offset]))
                {
                    offset += 1;
                }
                let token = std::str::from_utf8(&bytes[start..offset])
                    .map_err(|_| err!(EINVAL, "TUF_CANDIDATE_JSON"))?;
                let valid = if token.starts_with('-') {
                    token.parse::<i64>().is_ok()
                } else {
                    token.parse::<u64>().is_ok()
                };
                if !valid {
                    fail!(EINVAL, "TUF_CANDIDATE_JSON");
                }
                continue;
            }
            _ => (),
        }
        offset += 1;
    }
    Ok(())
}
fn strict_json(bytes: &[u8]) -> EnclaveResult<Value> {
    if bytes.is_empty() || bytes.len() > MAX_CHILD_BYTES {
        fail!(E2BIG, "TUF_CANDIDATE_SIZE");
    }
    integer_tokens(bytes)?;
    let mut parser = serde_json::Deserializer::from_slice(bytes);
    let mut remaining = MAX_NODES;
    let value = ValueSeed {
        depth: 0,
        remaining: &mut remaining,
    }
    .deserialize(&mut parser)
    .map_err(|_| err!(EINVAL, "TUF_CANDIDATE_JSON"))?;
    parser
        .end()
        .map_err(|_| err!(EINVAL, "TUF_CANDIDATE_JSON"))?;
    Ok(value)
}
fn object(value: &Value) -> EnclaveResult<&serde_json::Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| err!(EINVAL, "TUF_CANDIDATE_SCHEMA"))
}
fn keys(value: &Value, required: &[&str], optional: &[&str]) -> EnclaveResult<()> {
    let fields = object(value)?;
    if required.iter().any(|key| !fields.contains_key(*key))
        || fields
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        fail!(EINVAL, "TUF_CANDIDATE_SCHEMA");
    }
    Ok(())
}
fn text<'a>(value: &'a Value, key: &str) -> EnclaveResult<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| err!(EINVAL, "TUF_CANDIDATE_SCHEMA"))
}
fn number(value: &Value, key: &str) -> EnclaveResult<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| err!(EINVAL, "TUF_CANDIDATE_SCHEMA"))
}
fn lower_hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn envelope(mut value: Value) -> EnclaveResult<Signed<Value>> {
    keys(&value, &["signed", "signatures"], &[])?;
    let fields = value
        .as_object_mut()
        .ok_or_else(|| err!(EINVAL, "TUF_CANDIDATE_SCHEMA"))?;
    let signatures = fields
        .remove("signatures")
        .ok_or_else(|| err!(EINVAL, "TUF_CANDIDATE_SCHEMA"))?;
    let signatures = signatures
        .as_array()
        .ok_or_else(|| err!(EINVAL, "TUF_CANDIDATE_SCHEMA"))?;
    if signatures.is_empty() || signatures.len() > MAX_SIGNATURES {
        fail!(E2BIG, "TUF_CANDIDATE_SIGNATURE_BOUND");
    }
    let mut parsed = Vec::with_capacity(signatures.len());
    for signature in signatures {
        keys(signature, &["keyid", "sig"], &[])?;
        parsed.push(TufSignature {
            keyid: text(signature, "keyid")?.into(),
            sig: text(signature, "sig")?.into(),
        });
    }
    // Move the already duplicate-checked signed Value directly. Deserializing
    // it again through serde_json::from_value would reinterpret a literal map
    // using arbitrary_precision's private Number key and change signed bytes.
    let signed = fields
        .remove("signed")
        .ok_or_else(|| err!(EINVAL, "TUF_CANDIDATE_SCHEMA"))?;
    Ok(Signed {
        signed,
        signatures: parsed,
    })
}
fn signature_set(signed: &Signed<Value>, root: &RootMeta, role: Role) -> EnclaveResult<()> {
    let assignment = root
        .roles
        .get(role.name())
        .ok_or_else(|| err!(EACCES, "TUF_ROLE_MISSING"))?;
    let message = crate::canonical_json::to_canonical_json_bytes(&signed.signed)?;
    let mut previous: Option<&str> = None;
    for signature in &signed.signatures {
        if !lower_hex(&signature.keyid, 64) || !lower_hex(&signature.sig, 128) {
            fail!(EACCES, "TUF_CANDIDATE_SIGNATURE_INVALID");
        }
        if previous.is_some_and(|prior| prior >= signature.keyid.as_str()) {
            fail!(EACCES, "TUF_CANDIDATE_SIGNATURE_ORDER");
        }
        previous = Some(&signature.keyid);
        if !assignment.keyids.contains(&signature.keyid) {
            fail!(EACCES, "TUF_CANDIDATE_SIGNATURE_UNAUTHORIZED");
        }
        let key = root
            .keys
            .get(&signature.keyid)
            .ok_or_else(|| err!(EACCES, "TUF_CANDIDATE_SIGNATURE_UNAUTHORIZED"))?;
        if key.keyid()?.as_str() != signature.keyid {
            fail!(EACCES, "TUF_CANDIDATE_SIGNATURE_INVALID");
        }
        let key = key
            .verifying_key()
            .ok_or_else(|| err!(EACCES, "TUF_CANDIDATE_SIGNATURE_INVALID"))?;
        let raw = hex::decode(&signature.sig)
            .map_err(|_| err!(EACCES, "TUF_CANDIDATE_SIGNATURE_INVALID"))?;
        let signature = Signature::from_slice(&raw)
            .map_err(|_| err!(EACCES, "TUF_CANDIDATE_SIGNATURE_INVALID"))?;
        key.verify_strict(&message, &signature)
            .map_err(|_| err!(EACCES, "TUF_CANDIDATE_SIGNATURE_INVALID"))?;
    }
    // Preserve the standard implementation's threshold and legacy refusal, but
    // never inherit its policy of ignoring extra invalid/unauthorized entries.
    verify_threshold(signed, root, role)
}
fn role_schema(signed: &Value, role: Role) -> EnclaveResult<()> {
    let payload = match role {
        Role::Targets => "targets",
        Role::Snapshot | Role::Timestamp => "meta",
        _ => fail!(EINVAL, "TUF_CANDIDATE_ROLE"),
    };
    keys(
        signed,
        &["_type", "spec_version", "version", "expires", payload],
        &[],
    )?;
    if text(signed, "_type")? != role.name() || text(signed, "spec_version")? != SPEC_VERSION {
        fail!(EINVAL, "TUF_CANDIDATE_ROLE");
    }
    let entries = object(&signed[payload])?;
    if role != Role::Targets {
        let name = if role == Role::Snapshot {
            "targets.json"
        } else {
            "snapshot.json"
        };
        if entries.len() != 1 || !entries.contains_key(name) {
            fail!(EINVAL, "TUF_CANDIDATE_SCHEMA");
        }
        let child = &entries[name];
        keys(child, &["version", "length", "hashes"], &[])?;
        if number(child, "version")? == 0
            || number(child, "length")? == 0
            || number(child, "length")? > MAX_CHILD_BYTES as u64
        {
            fail!(EINVAL, "TUF_CANDIDATE_SCHEMA");
        }
        keys(&child["hashes"], &["sha256"], &[])?;
        if !lower_hex(text(&child["hashes"], "sha256")?, 64) {
            fail!(EINVAL, "TUF_CANDIDATE_SCHEMA");
        }
    } else {
        for target in entries.values() {
            keys(target, &["length", "hashes"], &["custom"])?;
            let _ = number(target, "length")?;
            keys(&target["hashes"], &["sha256", "blake3"], &[])?;
            for algorithm in ["sha256", "blake3"] {
                if !lower_hex(text(&target["hashes"], algorithm)?, 64) {
                    fail!(EINVAL, "TUF_CANDIDATE_SCHEMA");
                }
            }
        }
    }
    Ok(())
}

/// Verify a complete candidate attachment against pinned standard-TUF trust and
/// an independently approved expected commitment. Every supplied signature must
/// be sorted, distinct, authorized and valid, including entries above threshold.
/// Strict JSON and exact OLPC outer encoding are both required. Raw control
/// characters make an OLPC string incompatible with strict JSON; such child
/// envelopes refuse pending an explicit protocol precision, never relaxed parsing.
/// No parent intent/signature/freshness/enrollment policy is authenticated here.
pub fn verify_complete_child(
    client: &TufClient,
    expected: &ExpectedChild,
    bytes: &[u8],
    trusted_now: i64,
) -> EnclaveResult<ChildFacts> {
    if !matches!(expected.role, Role::Targets | Role::Snapshot)
        || expected.version == 0
        || trusted_now < 0
    {
        fail!(EINVAL, "TUF_CANDIDATE_ROLE");
    }
    if bytes.is_empty() || bytes.len() > MAX_CHILD_BYTES || expected.length > MAX_CHILD_BYTES as u64
    {
        fail!(E2BIG, "TUF_CANDIDATE_SIZE");
    }
    if bytes.len() as u64 != expected.length {
        fail!(EACCES, "TUF_CANDIDATE_LENGTH");
    }
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    if digest != expected.sha256 {
        fail!(EACCES, "TUF_CANDIDATE_HASH");
    }
    let value = strict_json(bytes)?;
    if crate::canonical_json::to_canonical_json_bytes(&value)? != bytes {
        fail!(EACCES, "TUF_CANDIDATE_OUTER_CANONICAL");
    }
    let signed = envelope(value)?;
    role_schema(&signed.signed, expected.role)?;
    let version = number(&signed.signed, "version")?;
    if version != expected.version {
        fail!(EACCES, "TUF_CANDIDATE_VERSION");
    }
    let root = &client.root.signed;
    check_expiry(&root.expires, trusted_now, Role::Root)?;
    check_expiry(text(&signed.signed, "expires")?, trusted_now, expected.role)?;
    // Reverify exact original signed root members, rather than accidentally
    // discarding extension fields via RootMeta typed reserialization.
    let current_root = client.chain.last().unwrap_or(&client.anchor);
    let root_envelope = envelope(strict_json(current_root)?)?;
    if text(&root_envelope.signed, "_type")? != "root"
        || number(&root_envelope.signed, "version")? != root.version
    {
        fail!(EACCES, "TUF_CANDIDATE_ROOT");
    }
    verify_threshold(&root_envelope, root, Role::Root)?;
    let previous = match expected.role {
        Role::Targets => client
            .targets
            .as_ref()
            .map(|(s, b)| (s.signed.version, b.as_slice())),
        Role::Snapshot => client
            .snapshot
            .as_ref()
            .map(|(s, b)| (s.signed.version, b.as_slice())),
        _ => unreachable!(),
    };
    if let Some((floor, old)) = previous {
        if version < floor {
            fail!(EACCES, "TUF_ROLLBACK");
        }
        if version == floor && bytes != old {
            fail!(EACCES, "TUF_EQUIVOCATION");
        }
    }
    signature_set(&signed, root, expected.role)?;
    let role_expiry = parse_rfc3339_utc(text(&signed.signed, "expires")?)
        .ok_or_else(|| err!(EINVAL, "TUF_BAD_EXPIRES"))?;
    let root_expiry =
        parse_rfc3339_utc(&root.expires).ok_or_else(|| err!(EINVAL, "TUF_BAD_EXPIRES"))?;
    Ok(ChildFacts {
        role: expected.role,
        version,
        length: expected.length,
        sha256: digest,
        signed_body_sha256: Sha256::digest(crate::canonical_json::to_canonical_json_bytes(
            &signed.signed,
        )?)
        .into(),
        root_version: root.version,
        valid_until_unix: root_expiry.min(role_expiry),
        signatures: signed.signatures.len(),
    })
}

/// Check a proposed parent signed member against an independently approved
/// commitment and exactly one complete signed child. This does not authenticate
/// the intent, sign the parent, grant authority or mutate/adopt trusted state.
/// Root/targets parents and delegated metadata are explicitly unsupported.
pub fn verify_parent_linkage(
    client: &TufClient,
    expected: &ExpectedParent,
    signed_body: &[u8],
    children: &[&[u8]],
    trusted_now: i64,
) -> EnclaveResult<ParentFacts> {
    let (child_role, name, floor) = match expected.role {
        Role::Snapshot => (
            Role::Targets,
            "targets.json",
            client
                .snapshot
                .as_ref()
                .map_or(0, |(s, _)| s.signed.version),
        ),
        Role::Timestamp => (
            Role::Snapshot,
            "snapshot.json",
            client
                .timestamp
                .as_ref()
                .map_or(0, |(s, _)| s.signed.version),
        ),
        _ => fail!(EINVAL, "TUF_CANDIDATE_PARENT_ROLE"),
    };
    if trusted_now < 0 || expected.linked_child.role != child_role {
        fail!(EINVAL, "TUF_CANDIDATE_PARENT_ROLE");
    }
    if children.len() != 1 {
        fail!(EINVAL, "TUF_CANDIDATE_PARENT_ATTACHMENTS");
    }
    if expected.base_version != floor {
        fail!(EACCES, "TUF_CANDIDATE_PARENT_BASE");
    }
    if expected.new_version <= expected.base_version {
        fail!(EACCES, "TUF_CANDIDATE_PARENT_VERSION");
    }
    if signed_body.is_empty()
        || signed_body.len() > MAX_CHILD_BYTES
        || expected.signed_body_bytes > MAX_CHILD_BYTES as u64
    {
        fail!(E2BIG, "TUF_CANDIDATE_SIZE");
    }
    if signed_body.len() as u64 != expected.signed_body_bytes {
        fail!(EACCES, "TUF_CANDIDATE_PARENT_LENGTH");
    }
    let digest: [u8; 32] = Sha256::digest(signed_body).into();
    if digest != expected.signed_body_sha256 {
        fail!(EACCES, "TUF_CANDIDATE_PARENT_HASH");
    }
    let body = strict_json(signed_body)?;
    if crate::canonical_json::to_canonical_json_bytes(&body)? != signed_body {
        fail!(EACCES, "TUF_CANDIDATE_OUTER_CANONICAL");
    }
    role_schema(&body, expected.role)?;
    if number(&body, "version")? != expected.new_version {
        fail!(EACCES, "TUF_CANDIDATE_PARENT_VERSION");
    }
    let expiry = text(&body, "expires")?;
    check_expiry(expiry, trusted_now, expected.role)?;
    let expiry = parse_rfc3339_utc(expiry).ok_or_else(|| err!(EINVAL, "TUF_BAD_EXPIRES"))?;
    let millis = u64::try_from(expiry)
        .ok()
        .and_then(|value| value.checked_mul(1000))
        .ok_or_else(|| err!(EINVAL, "TUF_CANDIDATE_PARENT_EXPIRY"))?;
    if millis != expected.expires_utc_ms {
        fail!(EACCES, "TUF_CANDIDATE_PARENT_EXPIRY");
    }
    let child = verify_complete_child(client, &expected.linked_child, children[0], trusted_now)?;
    let link = &body["meta"][name];
    if number(link, "version")? != child.version
        || number(link, "length")? != child.length
        || text(&link["hashes"], "sha256")? != hex::encode(child.sha256)
    {
        fail!(EACCES, "TUF_CANDIDATE_PARENT_LINK");
    }
    Ok(ParentFacts {
        role: expected.role,
        version: expected.new_version,
        signed_body_bytes: expected.signed_body_bytes,
        signed_body_sha256: digest,
        expires_utc_ms: millis,
        valid_until_unix: expiry.min(child.valid_until_unix),
        child,
    })
}

/// Independently authenticated commitments for a diagnostic root migration.
/// Root hashes cover canonical signed members, excluding outer signatures.
/// TUF assignment hashes cover OLPC canonical `{"keys": ..., "roles": ...}`.
/// Those assignments describe ordinary TUF keys/thresholds, not signer host,
/// custodian, deployment, restore or isolated hardware authority.
#[derive(Debug, Clone)]
pub struct ExpectedRootMigration {
    /// Exact current pinned version.
    pub base_version: u64,
    /// Exactly base + 1; gaps and overflow refuse.
    pub new_version: u64,
    /// SHA256 of the exact current canonical root signed member.
    pub old_root_signed_sha256: [u8; 32],
    /// SHA256 of the exact proposed canonical root signed member.
    pub new_root_signed_sha256: [u8; 32],
    /// Exact proposed canonical signed-member length.
    pub new_root_signed_bytes: u64,
    /// Exact proposed exclusive expiry in UTC milliseconds.
    pub expires_utc_ms: u64,
    /// Commitment to the current root's ordinary TUF keys and role assignments.
    pub old_tuf_assignment_sha256: [u8; 32],
    /// Commitment to the proposed root's ordinary TUF keys and role assignments.
    pub new_tuf_assignment_sha256: [u8; 32],
}

/// Root migration diagnostics; this is not adoption, approval or a capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootMigrationFacts {
    /// Exact pinned previous version.
    pub old_version: u64,
    /// Exact proposed version.
    pub new_version: u64,
    /// Exact complete proposed file length, including every signature.
    pub envelope_bytes: u64,
    /// SHA256 of the complete proposed file.
    pub envelope_sha256: [u8; 32],
    /// SHA256 of the proposed canonical root signed member.
    pub signed_body_sha256: [u8; 32],
    /// Number of supplied valid signatures authorized by the old root role.
    pub old_signatures: usize,
    /// Number of supplied valid signatures authorized by the new root role.
    pub new_signatures: usize,
    /// Earlier exclusive expiry of the old and proposed roots.
    pub valid_until_unix: i64,
}

// A deliberately closed candidate subset: all four top-level roles and only
// standard Ed25519 keys. Reject aliases before typed conversion can erase fields.
fn migration_root(value: &Value) -> EnclaveResult<RootMeta> {
    keys(
        value,
        &[
            "_type",
            "spec_version",
            "version",
            "expires",
            "keys",
            "roles",
            "consistent_snapshot",
        ],
        &[],
    )?;
    if text(value, "_type")? != "root"
        || text(value, "spec_version")? != SPEC_VERSION
        || number(value, "version")? == 0
        || !value["consistent_snapshot"].is_boolean()
    {
        fail!(EINVAL, "TUF_CANDIDATE_ROOT_SCHEMA");
    }
    let public = object(&value["keys"])?;
    if public.is_empty() || public.len() > MAX_SIGNATURES {
        fail!(E2BIG, "TUF_CANDIDATE_ROOT_KEYS");
    }
    let mut normalized = BTreeSet::new();
    for (id, key) in public {
        keys(key, &["keytype", "scheme", "keyval"], &[])?;
        keys(&key["keyval"], &["public"], &[])?;
        let material = text(&key["keyval"], "public")?;
        if text(key, "keytype")? != "ed25519"
            || text(key, "scheme")? != "ed25519"
            || !lower_hex(id, 64)
            || !lower_hex(material, 64)
        {
            fail!(EINVAL, "TUF_CANDIDATE_ROOT_KEY");
        }
        let parsed: TufKey = serde_json::from_value(key.clone())
            .map_err(|_| err!(EINVAL, "TUF_CANDIDATE_ROOT_KEY"))?;
        let verified = parsed
            .verifying_key()
            .ok_or_else(|| err!(EINVAL, "TUF_CANDIDATE_ROOT_KEY"))?;
        let canonical = verified.to_edwards().compress().to_bytes();
        // Key IDs hash their wire encoding; that alone cannot establish distinct
        // curve identities when a decoder accepts noncanonical Edwards points.
        if parsed.keyid()? != *id
            || material != hex::encode(canonical)
            || verified.is_weak()
            || !normalized.insert(canonical)
        {
            fail!(EINVAL, "TUF_CANDIDATE_ROOT_KEY");
        }
    }
    keys(
        &value["roles"],
        &["root", "targets", "snapshot", "timestamp"],
        &[],
    )?;
    for role in object(&value["roles"])?.values() {
        keys(role, &["keyids", "threshold"], &[])?;
        let ids = role["keyids"]
            .as_array()
            .ok_or_else(|| err!(EINVAL, "TUF_CANDIDATE_ROOT_POLICY"))?;
        let threshold = number(role, "threshold")?;
        if ids.is_empty()
            || ids.len() > MAX_SIGNATURES
            || threshold == 0
            || threshold > ids.len() as u64
        {
            fail!(EINVAL, "TUF_CANDIDATE_ROOT_POLICY");
        }
        let mut previous: Option<&str> = None;
        for id in ids {
            let id = id
                .as_str()
                .ok_or_else(|| err!(EINVAL, "TUF_CANDIDATE_ROOT_POLICY"))?;
            if !public.contains_key(id) || previous.is_some_and(|prior| prior >= id) {
                fail!(EINVAL, "TUF_CANDIDATE_ROOT_POLICY");
            }
            previous = Some(id);
        }
    }
    serde_json::from_value(value.clone()).map_err(|_| err!(EINVAL, "TUF_CANDIDATE_ROOT_SCHEMA"))
}
fn assignment_hash(value: &Value) -> EnclaveResult<[u8; 32]> {
    let assignment = serde_json::json!({"keys":&value["keys"],"roles":&value["roles"]});
    Ok(Sha256::digest(crate::canonical_json::to_canonical_json_bytes(&assignment)?).into())
}

/// Verify exact root migration bytes under BOTH ordinary old/new thresholds.
///
/// This strict diagnostic authenticates no intent, custodian policy or isolated
/// signer. The caller supplies independently authenticated commitments/current
/// client/time. Every supplied signature must be sorted, distinct, authorized by
/// at least one root role, and valid. No approval receipt replaces a TUF signature.
/// The current client and its adoption/version state are never mutated.
pub fn verify_root_migration(
    client: &TufClient,
    expected: &ExpectedRootMigration,
    proposed: &[u8],
    trusted_now: i64,
) -> EnclaveResult<RootMigrationFacts> {
    if trusted_now < 0 {
        fail!(EINVAL, "TUF_CANDIDATE_ROOT_TIME");
    }
    let old_bytes = client.chain.last().unwrap_or(&client.anchor);
    let old = envelope(strict_json(old_bytes)?)?;
    let old_root = migration_root(&old.signed)?;
    if old_root != client.root.signed {
        fail!(EACCES, "TUF_CANDIDATE_ROOT");
    }
    check_expiry(&old_root.expires, trusted_now, Role::Root)?;
    // A previously adopted rotation may retain valid retired-key signatures.
    // Its exact pinned body must satisfy its own threshold; do not reinterpret
    // historical extra signatures as newly supplied migration authority.
    verify_threshold(&old, &old_root, Role::Root)?;
    if expected.base_version != old_root.version
        || old_root.version.checked_add(1) != Some(expected.new_version)
    {
        fail!(EACCES, "TUF_CANDIDATE_ROOT_VERSION");
    }
    let old_body = crate::canonical_json::to_canonical_json_bytes(&old.signed)?;
    let old_hash: [u8; 32] = Sha256::digest(&old_body).into();
    if old_hash != expected.old_root_signed_sha256
        || assignment_hash(&old.signed)? != expected.old_tuf_assignment_sha256
    {
        fail!(EACCES, "TUF_CANDIDATE_ROOT_COMMITMENT");
    }
    let value = strict_json(proposed)?;
    if crate::canonical_json::to_canonical_json_bytes(&value)? != proposed {
        fail!(EACCES, "TUF_CANDIDATE_OUTER_CANONICAL");
    }
    let new = envelope(value)?;
    let new_root = migration_root(&new.signed)?;
    if new_root.version != expected.new_version {
        fail!(EACCES, "TUF_CANDIDATE_ROOT_VERSION");
    }
    let body = crate::canonical_json::to_canonical_json_bytes(&new.signed)?;
    let body_hash: [u8; 32] = Sha256::digest(&body).into();
    if body.len() as u64 != expected.new_root_signed_bytes
        || body_hash != expected.new_root_signed_sha256
        || assignment_hash(&new.signed)? != expected.new_tuf_assignment_sha256
    {
        fail!(EACCES, "TUF_CANDIDATE_ROOT_COMMITMENT");
    }
    check_expiry(&new_root.expires, trusted_now, Role::Root)?;
    let expiry =
        parse_rfc3339_utc(&new_root.expires).ok_or_else(|| err!(EINVAL, "TUF_BAD_EXPIRES"))?;
    let millis = u64::try_from(expiry)
        .ok()
        .and_then(|value| value.checked_mul(1000))
        .ok_or_else(|| err!(EINVAL, "TUF_CANDIDATE_ROOT_EXPIRY"))?;
    if millis != expected.expires_utc_ms {
        fail!(EACCES, "TUF_CANDIDATE_ROOT_EXPIRY");
    }
    let old_ids = &old_root.roles["root"].keyids;
    let new_ids = &new_root.roles["root"].keyids;
    let mut previous: Option<&str> = None;
    let mut old_count = 0;
    let mut new_count = 0;
    for signature in &new.signatures {
        let id = signature.keyid.as_str();
        if !lower_hex(id, 64)
            || !lower_hex(&signature.sig, 128)
            || previous.is_some_and(|prior| prior >= id)
        {
            fail!(EACCES, "TUF_CANDIDATE_SIGNATURE_ORDER");
        }
        previous = Some(id);
        let in_old = old_ids.iter().any(|old| old == id);
        let in_new = new_ids.iter().any(|new| new == id);
        let key = if in_old {
            &old_root.keys[id]
        } else if in_new {
            &new_root.keys[id]
        } else {
            fail!(EACCES, "TUF_CANDIDATE_SIGNATURE_UNAUTHORIZED")
        };
        let key = key
            .verifying_key()
            .ok_or_else(|| err!(EACCES, "TUF_CANDIDATE_SIGNATURE_INVALID"))?;
        let raw = hex::decode(&signature.sig)
            .map_err(|_| err!(EACCES, "TUF_CANDIDATE_SIGNATURE_INVALID"))?;
        let parsed = Signature::from_slice(&raw)
            .map_err(|_| err!(EACCES, "TUF_CANDIDATE_SIGNATURE_INVALID"))?;
        key.verify_strict(&body, &parsed)
            .map_err(|_| err!(EACCES, "TUF_CANDIDATE_SIGNATURE_INVALID"))?;
        old_count += usize::from(in_old);
        new_count += usize::from(in_new);
    }
    // The strict union check above rejects invalid/unknown extras; these calls
    // preserve ordinary TUF threshold and legacy-signature refusal semantics.
    verify_threshold(&new, &old_root, Role::Root)?;
    verify_threshold(&new, &new_root, Role::Root)?;
    let old_expiry =
        parse_rfc3339_utc(&old_root.expires).ok_or_else(|| err!(EINVAL, "TUF_BAD_EXPIRES"))?;
    Ok(RootMigrationFacts {
        old_version: old_root.version,
        new_version: new_root.version,
        envelope_bytes: proposed.len() as u64,
        envelope_sha256: Sha256::digest(proposed).into(),
        signed_body_sha256: body_hash,
        old_signatures: old_count,
        new_signatures: new_count,
        valid_until_unix: expiry.min(old_expiry),
    })
}

#[cfg(test)]
#[path = "candidate_tests.rs"]
mod tests;
