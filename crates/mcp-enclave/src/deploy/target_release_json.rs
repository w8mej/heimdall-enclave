//! Closed, bounded input subset for the software-release approval reader.
//! This preflight does not authenticate any input. Standard TUF does that next.

use std::collections::BTreeSet;
use enclave_core::{error::EnclaveResult, err, fail};
use enclave_crypto::{canonical_json, time::parse_rfc3339_utc,
    tuf::{MetaListing, Role, RootMeta, Signed, TargetsMeta, TufKey, SPEC_VERSION}};
use serde::{de::{DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor}, Deserialize, Serialize};
use serde_json::Value;

pub(super) const MAX_METADATA: usize = 1024 * 1024;
const MAX_DEPTH: usize = 64;
const MAX_NODES: usize = 65_536;
const MAX_KEYS: usize = 64;
// Persisted TufTrustedState contains exact metadata as strings. Metadata's
// closed field schemas impose their own smaller per-field bounds.
const MAX_STRING: usize = MAX_METADATA;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MinimumThresholds {
    pub(super) root: u32,
    pub(super) timestamp: u32,
    pub(super) snapshot: u32,
    pub(super) targets: u32,
}
impl MinimumThresholds {
    pub(super) fn valid(&self, l3: bool) -> bool {
        [self.root, self.timestamp, self.snapshot, self.targets].into_iter()
            .all(|v| (1..=MAX_KEYS as u32).contains(&v))
            && (!l3 || (self.root >= 2 && self.targets >= 2))
    }
    pub(super) fn preserves(&self, old: &Self) -> bool {
        self.root >= old.root && self.timestamp >= old.timestamp
            && self.snapshot >= old.snapshot && self.targets >= old.targets
    }
    fn role(&self, role: Role) -> u32 {
        match role { Role::Root => self.root, Role::Timestamp => self.timestamp,
            Role::Snapshot => self.snapshot, Role::Targets => self.targets }
    }
}

struct Seed<'a> { depth: usize, remaining: &'a mut usize }
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, parser: D) -> Result<Value, D::Error> {
        if self.depth > MAX_DEPTH || *self.remaining == 0 {
            return Err(serde::de::Error::custom("release JSON complexity"));
        }
        *self.remaining -= 1;
        parser.deserialize_any(JsonVisitor { depth: self.depth, remaining: self.remaining })
    }
}
struct JsonVisitor<'a> { depth: usize, remaining: &'a mut usize }
impl<'de> Visitor<'de> for JsonVisitor<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("bounded duplicate-free integer JSON")
    }
    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Value,E> { Ok(Value::Bool(v)) }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Value,E> { Ok(Value::Number(v.into())) }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Value,E> { Ok(Value::Number(v.into())) }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Value,E> { Err(E::custom("release JSON float")) }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Value,E> {
        if v.len() > MAX_STRING { return Err(E::custom("release JSON string")); }
        Ok(Value::String(v.into()))
    }
    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Value,E> {
        if v.len() > MAX_STRING { return Err(E::custom("release JSON string")); }
        Ok(Value::String(v))
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<Value,E> { Ok(Value::Null) }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Value,E> { Ok(Value::Null) }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value,A::Error> {
        let mut values=Vec::new();
        while let Some(value)=seq.next_element_seed(Seed {depth:self.depth+1, remaining:&mut *self.remaining})? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value,A::Error> {
        let mut values=serde_json::Map::new();
        while let Some(key)=map.next_key::<String>()? {
            if key.len()>MAX_STRING || values.contains_key(&key) {
                return Err(serde::de::Error::custom("release JSON duplicate or key bound"));
            }
            let value=map.next_value_seed(Seed {depth:self.depth+1, remaining:&mut *self.remaining})?;
            values.insert(key,value);
        }
        Ok(Value::Object(values))
    }
}

// arbitrary_precision can dispatch numeric tokens through visit_map. Validate
// unquoted number tokens before visitor dispatch; never rewrite quoted bytes.
fn integer_tokens(bytes: &[u8]) -> EnclaveResult<()> {
    let mut offset=0; let mut quoted=false;
    while offset<bytes.len() {
        match bytes[offset] {
            b'\\' if quoted => { offset+=2; continue; }
            b'"' => quoted=!quoted,
            b if !quoted && (b==b'-' || b.is_ascii_digit()) => {
                let start=offset; offset+=1;
                while offset<bytes.len() && (bytes[offset].is_ascii_digit() || b".-+eE".contains(&bytes[offset])) { offset+=1; }
                let token=std::str::from_utf8(&bytes[start..offset]).map_err(|_|err!(EINVAL,"RELEASE_JSON"))?;
                if !(if token.starts_with('-') {token.parse::<i64>().is_ok()} else {token.parse::<u64>().is_ok()}) {
                    fail!(EINVAL,"RELEASE_JSON");
                }
                continue;
            }
            _ => (),
        }
        offset+=1;
    }
    Ok(())
}
pub(super) fn strict(bytes: &[u8], maximum: usize) -> EnclaveResult<Value> {
    if bytes.is_empty() || bytes.len()>maximum { fail!(E2BIG,"RELEASE_JSON_BOUND"); }
    integer_tokens(bytes)?;
    let mut parser=serde_json::Deserializer::from_slice(bytes); let mut remaining=MAX_NODES;
    let value=Seed {depth:0, remaining:&mut remaining}.deserialize(&mut parser)
        .map_err(|_|err!(EINVAL,"RELEASE_JSON"))?;
    parser.end().map_err(|_|err!(EINVAL,"RELEASE_JSON"))?;
    Ok(value)
}
pub(super) fn object(v: &Value) -> EnclaveResult<&serde_json::Map<String,Value>> {
    v.as_object().ok_or_else(||err!(EINVAL,"RELEASE_SCHEMA"))
}
pub(super) fn closed(v: &Value, required: &[&str], optional: &[&str]) -> EnclaveResult<()> {
    let fields=object(v)?;
    if required.iter().any(|k|!fields.contains_key(*k))
        || fields.keys().any(|k|!required.contains(&k.as_str()) && !optional.contains(&k.as_str())) {
        fail!(EINVAL,"RELEASE_SCHEMA");
    }
    Ok(())
}
pub(super) fn text<'a>(v: &'a Value, key: &str) -> EnclaveResult<&'a str> {
    v.get(key).and_then(Value::as_str).ok_or_else(||err!(EINVAL,"RELEASE_SCHEMA"))
}
pub(super) fn uint(v: &Value, key: &str) -> EnclaveResult<u64> {
    v.get(key).and_then(Value::as_u64).ok_or_else(||err!(EINVAL,"RELEASE_SCHEMA"))
}
pub(super) fn lower_hex(v: &str, len: usize) -> bool {
    v.len()==len && v.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn positive(v: &Value, key: &str, max: u64) -> EnclaveResult<u64> {
    let n=uint(v,key)?;
    if n==0 || n>max { fail!(EINVAL,"RELEASE_SCHEMA"); }
    Ok(n)
}
fn hashes(v: &Value) -> EnclaveResult<()> {
    closed(v,&["sha256","blake3"],&[])?;
    if ["sha256","blake3"].into_iter().any(|k|text(v,k).map_or(true,|s|!lower_hex(s,64))) {
        fail!(EINVAL,"RELEASE_HASH_SCHEMA");
    }
    Ok(())
}
fn signed_matches<T: DeserializeOwned + Serialize>(bytes: &[u8], raw: &Value) -> EnclaveResult<()> {
    let typed: Signed<T>=serde_json::from_slice(bytes).map_err(|_|err!(EINVAL,"RELEASE_SCHEMA"))?;
    if canonical_json::to_canonical_json_value(&raw["signed"])?
        != canonical_json::to_canonical_json_bytes(&typed.signed)? {
        fail!(EINVAL,"RELEASE_SIGNED_REPRESENTATION");
    }
    Ok(())
}
fn root_schema(body: &Value, minimum: &MinimumThresholds) -> EnclaveResult<()> {
    closed(body,&["_type","spec_version","version","expires","keys","roles","consistent_snapshot"],&[])?;
    if body.get("consistent_snapshot")!=Some(&Value::Bool(false)) { fail!(EINVAL,"RELEASE_ROOT_SCHEMA"); }
    let keys=object(&body["keys"])?;
    if keys.is_empty() || keys.len()>MAX_KEYS { fail!(E2BIG,"RELEASE_ROOT_KEYS"); }
    let mut material=BTreeSet::new();
    for (id,key) in keys {
        closed(key,&["keytype","scheme","keyval"],&[])?;
        closed(&key["keyval"],&["public"],&[])?;
        let public=text(&key["keyval"],"public")?;
        if !lower_hex(id,64) || text(key,"keytype")?!="ed25519" || text(key,"scheme")?!="ed25519"
            || !lower_hex(public,64) || !material.insert(public) { fail!(EINVAL,"RELEASE_ROOT_KEY"); }
        let bytes: [u8;32]=hex::decode(public).map_err(|_|err!(EINVAL,"RELEASE_ROOT_KEY"))?
            .try_into().map_err(|_|err!(EINVAL,"RELEASE_ROOT_KEY"))?;
        let verified=ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_|err!(EINVAL,"RELEASE_ROOT_KEY"))?;
        if verified.is_weak() || verified.to_edwards().compress().to_bytes()!=bytes
            || TufKey::ed25519(&verified).keyid()?!=*id { fail!(EINVAL,"RELEASE_ROOT_KEY"); }
    }
    closed(&body["roles"],&["root","timestamp","snapshot","targets"],&[])?;
    for role in [Role::Root,Role::Timestamp,Role::Snapshot,Role::Targets] {
        let assignment=&body["roles"][role.name()];
        closed(assignment,&["keyids","threshold"],&[])?;
        let ids=assignment["keyids"].as_array().ok_or_else(||err!(EINVAL,"RELEASE_ROOT_ROLE"))?;
        let threshold=positive(assignment,"threshold",MAX_KEYS as u64)?;
        if ids.is_empty() || ids.len()>MAX_KEYS || threshold>ids.len() as u64
            || threshold<u64::from(minimum.role(role)) { fail!(EACCES,"RELEASE_ROOT_THRESHOLD"); }
        let mut seen=BTreeSet::new();
        for id in ids {
            let id=id.as_str().ok_or_else(||err!(EINVAL,"RELEASE_ROOT_ROLE"))?;
            if !keys.contains_key(id) || !seen.insert(id) { fail!(EINVAL,"RELEASE_ROOT_ROLE"); }
        }
    }
    Ok(())
}

/// Validate exactly the subset consumed by the fixed local approval loader.
/// Standard TUF signature/rotation/expiry/rollback checks remain mandatory.
pub(super) fn metadata(bytes: &[u8], role: Role, minimum: &MinimumThresholds,
    inventory_target: &str) -> EnclaveResult<()> {
    let raw=strict(bytes,MAX_METADATA)?;
    closed(&raw,&["signed","signatures"],&[])?;
    let signatures=raw["signatures"].as_array().ok_or_else(||err!(EINVAL,"RELEASE_SIGNATURE_SCHEMA"))?;
    if signatures.is_empty() || signatures.len()>MAX_KEYS { fail!(E2BIG,"RELEASE_SIGNATURE_BOUND"); }
    let mut seen=BTreeSet::new();
    for signature in signatures {
        closed(signature,&["keyid","sig"],&[])?;
        let id=text(signature,"keyid")?;
        if !lower_hex(id,64) || !lower_hex(text(signature,"sig")?,128) || !seen.insert(id) {
            fail!(EINVAL,"RELEASE_SIGNATURE_SCHEMA");
        }
    }
    let body=&raw["signed"];
    if text(body,"_type")?!=role.name() || text(body,"spec_version")?!=SPEC_VERSION
        || positive(body,"version",u32::MAX as u64)?==0
        || parse_rfc3339_utc(text(body,"expires")?).is_none() { fail!(EINVAL,"RELEASE_ROLE_SCHEMA"); }
    match role {
        Role::Root => { root_schema(body,minimum)?; signed_matches::<RootMeta>(bytes,&raw)?; }
        Role::Timestamp | Role::Snapshot => {
            closed(body,&["_type","spec_version","version","expires","meta"],&[])?;
            let child=if role==Role::Timestamp {"snapshot.json"} else {"targets.json"};
            closed(&body["meta"],&[child],&[])?;
            let entry=&body["meta"][child];
            closed(entry,&["version","length","hashes"],&[])?;
            positive(entry,"version",u32::MAX as u64)?;
            positive(entry,"length",MAX_METADATA as u64)?;
            hashes(&entry["hashes"])?;
            signed_matches::<MetaListing>(bytes,&raw)?;
        }
        Role::Targets => {
            closed(body,&["_type","spec_version","version","expires","targets"],&[])?;
            closed(&body["targets"],&[inventory_target],&[])?;
            let entry=&body["targets"][inventory_target];
            closed(entry,&["length","hashes"],&[])?;
            positive(entry,"length",MAX_METADATA as u64)?;
            hashes(&entry["hashes"])?;
            signed_matches::<TargetsMeta>(bytes,&raw)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path="target_release_json_tests.rs"]
mod tests;
