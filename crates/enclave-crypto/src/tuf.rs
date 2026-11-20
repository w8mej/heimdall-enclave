//! TUF 4-role metadata verification (`root`, `timestamp`, `snapshot`,
//! `targets`) — the shared engine used by UID 702 (artifact admission),
//! UID 703 (`fido-mds-allowlist.json` freshness), UID 705 (`vk_manifest.json`,
//! fleet `UnquarantineGrant`s).
//!
//! Defences implemented (TUF spec §5 client workflow):
//! * **Threshold signatures** by distinct authorized key IDs per role.
//! * **Root rotation**: `N+1` must be signed by a threshold of *both* the
//!   trusted root `N` and itself; versions advance by exactly one.
//! * **Rollback**: timestamp/snapshot/targets versions never decrease; an
//!   equal version must be byte-identical (no equivocation); per FS-702 §7.3 a
//!   *changed* document must strictly increase its version.
//! * **Freeze**: every role's `expires` is checked against a trusted clock
//!   that never moves backwards (monotonic anchor + high-water mark).
//! * **Mix-and-match**: snapshot binds the exact `targets.json` version (and
//!   hashes, when present); timestamp binds the snapshot version and hashes.
//! * **Dual-hash targets**: every target carries `blake3` **and** `sha256`.
//!
//! Signatures are Ed25519 over OLPC Canonical JSON of `signed`; key IDs are
//! `hex(SHA-256(OLPC(key)))`. Application approval intents separately use JCS.
//! Legacy JCS signatures are detected and refused with an explicit migration error.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::time::parse_rfc3339_utc;

/// Bounded complete-child checks for the disabled guarded signer candidate.
pub mod candidate;

/// TUF spec version string emitted by MCPMac tooling.
pub const SPEC_VERSION: &str = "1.0.31";

/// The four top-level roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Root of trust.
    Root,
    /// Freshness.
    Timestamp,
    /// Consistency.
    Snapshot,
    /// Artifact hashes.
    Targets,
}

impl Role {
    /// Role name.
    pub fn name(self) -> &'static str {
        match self {
            Role::Root => "root",
            Role::Timestamp => "timestamp",
            Role::Snapshot => "snapshot",
            Role::Targets => "targets",
        }
    }
}

/// Public key entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TufKey {
    /// `ed25519`.
    pub keytype: String,
    /// `ed25519`.
    pub scheme: String,
    /// `{ "public": hex }`.
    pub keyval: BTreeMap<String, String>,
}

impl TufKey {
    /// Wrap an Ed25519 verifying key.
    pub fn ed25519(vk: &VerifyingKey) -> Self {
        let mut kv = BTreeMap::new();
        kv.insert("public".to_owned(), hex::encode(vk.to_bytes()));
        Self {
            keytype: "ed25519".into(),
            scheme: "ed25519".into(),
            keyval: kv,
        }
    }
    /// Key ID: hex(SHA-256(canonical_json(key))) per TUF/securesystemslib (GAP-31).
    pub fn keyid(&self) -> EnclaveResult<String> {
        Ok(hex::encode(Sha256::digest(
            crate::canonical_json::to_canonical_json_bytes(self)?,
        )))
    }
    /// Legacy RFC 8785 JCS key ID (for migration and legacy detection).
    pub fn legacy_jcs_keyid(&self) -> EnclaveResult<String> {
        Ok(hex::encode(Sha256::digest(
            enclave_core::jcs::to_jcs_bytes(self)?,
        )))
    }
    fn verifying_key(&self) -> Option<VerifyingKey> {
        if self.keytype != "ed25519" || self.scheme != "ed25519" {
            return None;
        }
        let b = hex::decode(self.keyval.get("public")?).ok()?;
        VerifyingKey::from_bytes(&b.try_into().ok()?).ok()
    }
}

/// Role key assignment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleKeys {
    /// Authorized key IDs.
    pub keyids: Vec<String>,
    /// Threshold.
    pub threshold: u32,
}

/// One signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TufSignature {
    /// Key ID.
    pub keyid: String,
    /// Hex signature.
    pub sig: String,
}

/// Signed envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Signed<T> {
    /// Signed body.
    pub signed: T,
    /// Signatures.
    pub signatures: Vec<TufSignature>,
}

/// `root.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RootMeta {
    /// `root`.
    pub _type: String,
    /// Spec version.
    pub spec_version: String,
    /// Version.
    pub version: u64,
    /// Expiry (RFC 3339 UTC).
    pub expires: String,
    /// Keys.
    pub keys: BTreeMap<String, TufKey>,
    /// Role assignments.
    pub roles: BTreeMap<String, RoleKeys>,
    /// Consistent snapshots.
    #[serde(default)]
    pub consistent_snapshot: bool,
}

/// A `meta` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaFile {
    /// Version of the referenced metadata.
    pub version: u64,
    /// Length.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub length: Option<u64>,
    /// Hashes.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub hashes: Option<BTreeMap<String, String>>,
}

/// `timestamp.json` / `snapshot.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetaListing {
    /// `timestamp` | `snapshot`.
    pub _type: String,
    /// Spec version.
    pub spec_version: String,
    /// Version.
    pub version: u64,
    /// Expiry.
    pub expires: String,
    /// Referenced metadata.
    pub meta: BTreeMap<String, MetaFile>,
}

/// One target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TargetFile {
    /// Length in bytes.
    pub length: u64,
    /// MUST contain `blake3` and `sha256`.
    pub hashes: BTreeMap<String, String>,
    /// MCPMac custom fields (classification, min_profile, license_policy, ...).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub custom: Option<Value>,
}

/// Delegated role assignment (GAP-31).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegatedRole {
    /// Role name.
    pub name: String,
    /// Authorized key IDs.
    pub keyids: Vec<String>,
    /// Signature threshold.
    pub threshold: u32,
    /// Whether this delegation is terminating.
    #[serde(default)]
    pub terminating: bool,
    /// Path patterns (Unix shell glob style).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub paths: Option<Vec<String>>,
    /// Path hash prefixes.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub path_hash_prefixes: Option<Vec<String>>,
}

impl DelegatedRole {
    /// Check whether a target path matches this delegation's path patterns.
    pub fn matches_target(&self, target_path: &str) -> bool {
        if let Some(paths) = &self.paths {
            for pattern in paths {
                if target_matches_pattern(target_path, pattern) {
                    return true;
                }
            }
        }
        false
    }
}

/// Delegations section in `targets.json` (GAP-31).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegations {
    /// Delegated keys: keyid -> TufKey.
    pub keys: BTreeMap<String, TufKey>,
    /// Delegated role definitions.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub roles: Option<Vec<DelegatedRole>>,
}

fn target_matches_pattern(target: &str, pattern: &str) -> bool {
    let t_parts: Vec<&str> = target.split('/').collect();
    let p_parts: Vec<&str> = pattern.split('/').collect();
    if t_parts.len() != p_parts.len() {
        return false;
    }
    for (t, p) in t_parts.iter().zip(p_parts.iter()) {
        if !glob_segment_matches(p, t) {
            return false;
        }
    }
    true
}

fn glob_segment_matches(pattern: &str, text: &str) -> bool {
    let p_bytes = pattern.as_bytes();
    let t_bytes = text.as_bytes();
    let mut p_idx = 0;
    let mut t_idx = 0;
    let mut star_idx = None;
    let mut match_idx = 0;

    while t_idx < t_bytes.len() {
        if p_idx < p_bytes.len() && (p_bytes[p_idx] == b'?' || p_bytes[p_idx] == t_bytes[t_idx]) {
            p_idx += 1;
            t_idx += 1;
        } else if p_idx < p_bytes.len() && p_bytes[p_idx] == b'*' {
            star_idx = Some(p_idx);
            p_idx += 1;
            match_idx = t_idx;
        } else if let Some(star) = star_idx {
            p_idx = star + 1;
            match_idx += 1;
            t_idx = match_idx;
        } else {
            return false;
        }
    }
    while p_idx < p_bytes.len() && p_bytes[p_idx] == b'*' {
        p_idx += 1;
    }
    p_idx == p_bytes.len()
}

/// `targets.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TargetsMeta {
    /// `targets`.
    pub _type: String,
    /// Spec version.
    pub spec_version: String,
    /// Version.
    pub version: u64,
    /// Expiry.
    pub expires: String,
    /// Targets.
    pub targets: BTreeMap<String, TargetFile>,
    /// Delegations (optional).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub delegations: Option<Delegations>,
}

/// Sign a metadata body with the given keys (repository / CI side).
pub fn sign<T: Serialize + Clone>(body: &T, keys: &[&SigningKey]) -> EnclaveResult<Signed<T>> {
    let msg = crate::canonical_json::to_canonical_json_bytes(body)?;
    let mut sigs = Vec::new();
    for k in keys {
        let keyid = TufKey::ed25519(&k.verifying_key()).keyid()?;
        sigs.push(TufSignature {
            keyid,
            sig: hex::encode(k.sign(&msg).to_bytes()),
        });
    }
    Ok(Signed {
        signed: body.clone(),
        signatures: sigs,
    })
}

fn check_legacy_jcs_signature<T: Serialize>(
    s: &Signed<T>,
    root: &RootMeta,
    role: Role,
) -> EnclaveResult<()> {
    let rk = root
        .roles
        .get(role.name())
        .ok_or_else(|| err!(EACCES, "TUF_ROLE_MISSING", "{}", role.name()))?;
    let jcs_msg = enclave_core::jcs::to_jcs_bytes(&s.signed)?;
    let mut good: BTreeSet<&str> = BTreeSet::new();
    for sig in &s.signatures {
        for (kid, key) in &root.keys {
            let legacy_id = key.legacy_jcs_keyid().unwrap_or_default();
            let modern_id = key.keyid().unwrap_or_default();
            if sig.keyid != legacy_id && sig.keyid != modern_id {
                continue;
            }
            if !rk.keyids.contains(kid)
                && !rk.keyids.contains(&legacy_id)
                && !rk.keyids.contains(&modern_id)
            {
                continue;
            }
            if good.contains(kid.as_str()) {
                continue;
            }
            let Some(vk) = key.verifying_key() else {
                continue;
            };
            let Ok(raw) = hex::decode(&sig.sig) else {
                continue;
            };
            let Ok(sg) = Signature::from_slice(&raw) else {
                continue;
            };
            if vk.verify_strict(&jcs_msg, &sg).is_ok() {
                good.insert(kid.as_str());
            }
        }
    }
    if (good.len() as u32) >= rk.threshold {
        Ok(())
    } else {
        fail!(EACCES, "NOT_LEGACY_VALID");
    }
}

fn verify_threshold<T: Serialize>(s: &Signed<T>, root: &RootMeta, role: Role) -> EnclaveResult<()> {
    let rk = root
        .roles
        .get(role.name())
        .ok_or_else(|| err!(EACCES, "TUF_ROLE_MISSING", "{}", role.name()))?;
    if rk.threshold == 0 {
        fail!(EACCES, "TUF_ZERO_THRESHOLD", "{}", role.name());
    }
    let msg = crate::canonical_json::to_canonical_json_bytes(&s.signed)?;
    let mut good: BTreeSet<&str> = BTreeSet::new();
    for sig in &s.signatures {
        if !rk.keyids.iter().any(|k| k == &sig.keyid) || good.contains(sig.keyid.as_str()) {
            continue;
        }
        let Some(key) = root.keys.get(&sig.keyid) else {
            continue;
        };
        // The key ID must actually be the hash of the key (no aliasing).
        if key.keyid().ok().as_deref() != Some(sig.keyid.as_str()) {
            continue;
        }
        let Some(vk) = key.verifying_key() else {
            continue;
        };
        let Ok(raw) = hex::decode(&sig.sig) else {
            continue;
        };
        let Ok(sg) = Signature::from_slice(&raw) else {
            continue;
        };
        if vk.verify_strict(&msg, &sg).is_ok() {
            good.insert(sig.keyid.as_str());
        }
    }
    if (good.len() as u32) < rk.threshold {
        if check_legacy_jcs_signature(s, root, role).is_ok() {
            fail!(
                EACCES,
                "TUF_CANONICALISATION_LEGACY",
                "{}: signed with legacy RFC 8785 JCS, canonical JSON required (run migrate-canonical)",
                role.name()
            );
        }
        fail!(
            EACCES,
            "TUF_THRESHOLD_NOT_MET",
            "{}: {} of {}",
            role.name(),
            good.len(),
            rk.threshold
        );
    }
    Ok(())
}

fn check_type(t: &str, want: &str) -> EnclaveResult<()> {
    if t != want {
        fail!(EINVAL, "TUF_WRONG_TYPE", "{t} != {want}");
    }
    Ok(())
}

fn check_expiry(expires: &str, now: i64, role: Role) -> EnclaveResult<()> {
    let e = parse_rfc3339_utc(expires).ok_or_else(|| err!(EINVAL, "TUF_BAD_EXPIRES"))?;
    if now >= e {
        fail!(
            ESTALE,
            "TUF_METADATA_EXPIRED",
            "{} expired at {expires}",
            role.name()
        );
    }
    Ok(())
}

fn check_hashes(want: &MetaFile, bytes: &[u8]) -> EnclaveResult<()> {
    if let Some(l) = want.length {
        if l != bytes.len() as u64 {
            fail!(EACCES, "TUF_LENGTH_MISMATCH");
        }
    }
    if let Some(h) = &want.hashes {
        for (alg, hx) in h {
            let got = match alg.as_str() {
                "sha256" => hex::encode(Sha256::digest(bytes)),
                "blake3" => blake3::hash(bytes).to_hex().to_string(),
                _ => fail!(EINVAL, "TUF_UNKNOWN_HASH", "{alg}"),
            };
            if &got != hx {
                fail!(EACCES, "TUF_HASH_MISMATCH", "{alg}");
            }
        }
    }
    Ok(())
}

fn parse<T: DeserializeOwned>(bytes: &[u8]) -> EnclaveResult<Signed<T>> {
    serde_json::from_slice(bytes).map_err(|e| err!(EINVAL, "TUF_PARSE", "{e}"))
}

/// Trusted wall clock that never moves backwards (FS-702 §7.3: expiry
/// evaluated against a monotonic delta so NTP rollback cannot un-expire).
#[derive(Debug, Clone)]
pub struct TrustedClock {
    anchor_wall: i64,
    anchor_mono: std::time::Instant,
    high_water: i64,
}

impl TrustedClock {
    /// Anchor at a wall-clock reading.
    pub fn anchored(wall: i64) -> Self {
        Self {
            anchor_wall: wall,
            anchor_mono: std::time::Instant::now(),
            high_water: wall,
        }
    }
    /// Resume after a restart from a persisted high-water mark (GAP-30): the
    /// clock restarts at `max(wall, high_water)`, so setting the wall clock
    /// back across a restart cannot un-expire metadata.
    pub fn resumed(wall: i64, high_water: i64) -> Self {
        Self::anchored(wall.max(high_water))
    }
    /// Current trusted time: `max(anchor + monotonic elapsed, reported wall, high water)`.
    pub fn now(&mut self, reported_wall: i64) -> i64 {
        let mono = self.anchor_wall + self.anchor_mono.elapsed().as_secs() as i64;
        self.high_water = self.high_water.max(mono).max(reported_wall);
        self.high_water
    }
    /// The high-water mark to persist.
    pub fn high_water(&self) -> i64 {
        self.high_water
    }
}

/// Persistable trusted metadata (GAP-30): the pinned anchor root, every
/// verified root rotation after it, and the exact bytes of the trusted
/// timestamp / snapshot / targets. Restoring re-verifies everything against
/// the chain, so the stored copy is a rollback floor, not a trust source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TufTrustedState {
    /// Format version.
    pub v: u8,
    /// Pinned root the chain starts from.
    pub anchor: String,
    /// Root rotations `N+1, N+2, ...`, in order.
    pub roots: Vec<String>,
    /// Trusted `timestamp.json`.
    pub timestamp: Option<String>,
    /// Trusted `snapshot.json`.
    pub snapshot: Option<String>,
    /// Trusted `targets.json`.
    pub targets: Option<String>,
}

fn utf8(b: &[u8]) -> EnclaveResult<String> {
    String::from_utf8(b.to_vec()).map_err(|_| err!(EINVAL, "TUF_PARSE", "metadata is not UTF-8"))
}

/// Client-side trusted state.
#[derive(Debug, Clone)]
pub struct TufClient {
    anchor: Vec<u8>,
    chain: Vec<Vec<u8>>,
    root: Signed<RootMeta>,
    timestamp: Option<(Signed<MetaListing>, Vec<u8>)>,
    snapshot: Option<(Signed<MetaListing>, Vec<u8>)>,
    targets: Option<(Signed<TargetsMeta>, Vec<u8>)>,
}

impl TufClient {
    /// Bootstrap from a pinned (out-of-band trusted) root. The root must be
    /// self-signed to threshold.
    pub fn bootstrap(root_bytes: &[u8]) -> EnclaveResult<Self> {
        let root: Signed<RootMeta> = parse(root_bytes)?;
        check_type(&root.signed._type, "root")?;
        verify_threshold(&root, &root.signed, Role::Root)?;
        for r in [Role::Root, Role::Timestamp, Role::Snapshot, Role::Targets] {
            if !root.signed.roles.contains_key(r.name()) {
                fail!(EINVAL, "TUF_ROLE_MISSING", "{}", r.name());
            }
        }
        Ok(Self {
            anchor: root_bytes.to_vec(),
            chain: Vec::new(),
            root,
            timestamp: None,
            snapshot: None,
            targets: None,
        })
    }

    /// Restore persisted trusted state: re-bootstrap from its anchor, replay
    /// the root chain, then re-verify the stored timestamp / snapshot /
    /// targets against it. Expiry is *not* checked here (expired state is
    /// still the rollback floor; freshness is enforced on use), so a restart
    /// never lowers the accepted versions.
    pub fn restore(state: &TufTrustedState) -> EnclaveResult<Self> {
        if state.v != 1 {
            fail!(EINVAL, "TUF_STATE_VERSION", "{}", state.v);
        }
        let mut c = Self::bootstrap(state.anchor.as_bytes())?;
        for r in &state.roots {
            c.update_root(r.as_bytes())?;
        }
        if let Some(t) = &state.timestamp {
            c.adopt_timestamp(t.as_bytes(), None)?;
        }
        if let Some(s) = &state.snapshot {
            c.adopt_snapshot(s.as_bytes(), None)?;
        }
        if let Some(t) = &state.targets {
            c.adopt_targets(t.as_bytes(), None)?;
        }
        Ok(c)
    }

    /// Export the trusted state for persistence.
    pub fn export(&self) -> EnclaveResult<TufTrustedState> {
        Ok(TufTrustedState {
            v: 1,
            anchor: utf8(&self.anchor)?,
            roots: self
                .chain
                .iter()
                .map(|r| utf8(r))
                .collect::<EnclaveResult<_>>()?,
            timestamp: self.timestamp.as_ref().map(|t| utf8(&t.1)).transpose()?,
            snapshot: self.snapshot.as_ref().map(|t| utf8(&t.1)).transpose()?,
            targets: self.targets.as_ref().map(|t| utf8(&t.1)).transpose()?,
        })
    }

    /// Whether `root_bytes` is the anchor or one of the verified rotations.
    pub fn chain_contains(&self, root_bytes: &[u8]) -> bool {
        self.anchor == root_bytes || self.chain.iter().any(|r| r == root_bytes)
    }

    /// Trusted root.
    pub fn root(&self) -> &RootMeta {
        &self.root.signed
    }

    /// Rotate to root `N+1`.
    pub fn update_root(&mut self, bytes: &[u8]) -> EnclaveResult<()> {
        let new: Signed<RootMeta> = parse(bytes)?;
        check_type(&new.signed._type, "root")?;
        if new.signed.version != self.root.signed.version + 1 {
            fail!(
                EACCES,
                "TUF_ROOT_VERSION",
                "{} -> {}",
                self.root.signed.version,
                new.signed.version
            );
        }
        verify_threshold(&new, &self.root.signed, Role::Root)?;
        verify_threshold(&new, &new.signed, Role::Root)?;
        let old = std::mem::replace(&mut self.root, new);
        self.chain.push(bytes.to_vec());
        // Key rotation of timestamp/snapshot invalidates their trusted copies (TUF §5.3.11).
        for r in [Role::Timestamp, Role::Snapshot] {
            if old.signed.roles.get(r.name()) != self.root.signed.roles.get(r.name()) {
                self.timestamp = None;
                self.snapshot = None;
            }
        }
        Ok(())
    }

    /// Verify and adopt a new `timestamp.json`.
    pub fn update_timestamp(&mut self, bytes: &[u8], now: i64) -> EnclaveResult<()> {
        self.adopt_timestamp(bytes, Some(now))
    }

    fn adopt_timestamp(&mut self, bytes: &[u8], now: Option<i64>) -> EnclaveResult<()> {
        if let Some(now) = now {
            check_expiry(&self.root.signed.expires, now, Role::Root)?;
        }
        let ts: Signed<MetaListing> = parse(bytes)?;
        check_type(&ts.signed._type, "timestamp")?;
        verify_threshold(&ts, &self.root.signed, Role::Timestamp)?;
        let snap_ref = ts
            .signed
            .meta
            .get("snapshot.json")
            .ok_or_else(|| err!(EINVAL, "TUF_NO_SNAPSHOT_META"))?;
        if let Some((old, old_bytes)) = &self.timestamp {
            if ts.signed.version < old.signed.version {
                fail!(
                    EACCES,
                    "TUF_ROLLBACK",
                    "timestamp {} < {}",
                    ts.signed.version,
                    old.signed.version
                );
            }
            if ts.signed.version == old.signed.version && bytes != old_bytes.as_slice() {
                fail!(
                    EACCES,
                    "TUF_EQUIVOCATION",
                    "timestamp v{} changed without a version bump",
                    ts.signed.version
                );
            }
            let old_snap = old
                .signed
                .meta
                .get("snapshot.json")
                .map_or(0, |m| m.version);
            if snap_ref.version < old_snap {
                fail!(
                    EACCES,
                    "TUF_ROLLBACK",
                    "snapshot ref {} < {}",
                    snap_ref.version,
                    old_snap
                );
            }
        }
        if let Some(now) = now {
            check_expiry(&ts.signed.expires, now, Role::Timestamp)?;
        }
        self.timestamp = Some((ts, bytes.to_vec()));
        Ok(())
    }

    /// Verify and adopt `snapshot.json`.
    pub fn update_snapshot(&mut self, bytes: &[u8], now: i64) -> EnclaveResult<()> {
        self.adopt_snapshot(bytes, Some(now))
    }

    fn adopt_snapshot(&mut self, bytes: &[u8], now: Option<i64>) -> EnclaveResult<()> {
        let (ts, _) = self
            .timestamp
            .as_ref()
            .ok_or_else(|| err!(EPERM, "TUF_ORDER", "timestamp first"))?;
        let want = ts
            .signed
            .meta
            .get("snapshot.json")
            .ok_or_else(|| err!(EINVAL, "TUF_NO_SNAPSHOT_META"))?
            .clone();
        check_hashes(&want, bytes)?;
        let snap: Signed<MetaListing> = parse(bytes)?;
        check_type(&snap.signed._type, "snapshot")?;
        verify_threshold(&snap, &self.root.signed, Role::Snapshot)?;
        if snap.signed.version != want.version {
            fail!(
                EACCES,
                "TUF_SNAPSHOT_VERSION_MISMATCH",
                "{} != {}",
                snap.signed.version,
                want.version
            );
        }
        let tref = snap
            .signed
            .meta
            .get("targets.json")
            .ok_or_else(|| err!(EINVAL, "TUF_NO_TARGETS_META"))?;
        if let Some((old, old_bytes)) = &self.snapshot {
            if snap.signed.version < old.signed.version {
                fail!(EACCES, "TUF_ROLLBACK", "snapshot");
            }
            if snap.signed.version == old.signed.version && bytes != old_bytes.as_slice() {
                fail!(EACCES, "TUF_EQUIVOCATION", "snapshot");
            }
            for (name, m) in &old.signed.meta {
                match snap.signed.meta.get(name) {
                    Some(n) if n.version >= m.version => {}
                    _ => fail!(
                        EACCES,
                        "TUF_ROLLBACK",
                        "{name} dropped or rolled back in snapshot"
                    ),
                }
            }
        }
        let _ = tref;
        if let Some(now) = now {
            check_expiry(&snap.signed.expires, now, Role::Snapshot)?;
        }
        self.snapshot = Some((snap, bytes.to_vec()));
        Ok(())
    }

    /// Verify and adopt `targets.json`.
    pub fn update_targets(&mut self, bytes: &[u8], now: i64) -> EnclaveResult<()> {
        self.adopt_targets(bytes, Some(now))
    }

    fn adopt_targets(&mut self, bytes: &[u8], now: Option<i64>) -> EnclaveResult<()> {
        let (snap, _) = self
            .snapshot
            .as_ref()
            .ok_or_else(|| err!(EPERM, "TUF_ORDER", "snapshot first"))?;
        let want = snap
            .signed
            .meta
            .get("targets.json")
            .ok_or_else(|| err!(EINVAL, "TUF_NO_TARGETS_META"))?
            .clone();
        check_hashes(&want, bytes)?;
        let t: Signed<TargetsMeta> = parse(bytes)?;
        check_type(&t.signed._type, "targets")?;
        verify_threshold(&t, &self.root.signed, Role::Targets)?;
        if t.signed.version != want.version {
            fail!(
                EACCES,
                "TUF_TARGETS_VERSION_MISMATCH",
                "mix-and-match: {} != {}",
                t.signed.version,
                want.version
            );
        }
        if let Some((old, old_bytes)) = &self.targets {
            if t.signed.version < old.signed.version {
                fail!(EACCES, "TUF_ROLLBACK", "targets");
            }
            if t.signed.version == old.signed.version && bytes != old_bytes.as_slice() {
                fail!(EACCES, "TUF_EQUIVOCATION", "targets");
            }
        }
        for (name, tf) in &t.signed.targets {
            if !tf.hashes.contains_key("blake3") || !tf.hashes.contains_key("sha256") {
                fail!(
                    EINVAL,
                    "TUF_TARGET_SINGLE_HASH",
                    "{name} must carry blake3 and sha256"
                );
            }
        }
        if let Some(now) = now {
            check_expiry(&t.signed.expires, now, Role::Targets)?;
        }
        self.targets = Some((t, bytes.to_vec()));
        Ok(())
    }

    /// Full refresh in the mandated order.
    pub fn refresh(
        &mut self,
        timestamp: &[u8],
        snapshot: &[u8],
        targets: &[u8],
        now: i64,
    ) -> EnclaveResult<()> {
        // Work on a copy so a failure leaves the trusted state untouched.
        let mut next = self.clone();
        next.update_timestamp(timestamp, now)?;
        next.update_snapshot(snapshot, now)?;
        next.update_targets(targets, now)?;
        *self = next;
        Ok(())
    }

    /// Ensure all metadata is still fresh at `now` (freeze defence on use).
    pub fn ensure_fresh(&self, now: i64) -> EnclaveResult<()> {
        check_expiry(&self.root.signed.expires, now, Role::Root)?;
        let ts = self
            .timestamp
            .as_ref()
            .ok_or_else(|| err!(ESTALE, "TUF_NOT_REFRESHED"))?;
        check_expiry(&ts.0.signed.expires, now, Role::Timestamp)?;
        let sn = self
            .snapshot
            .as_ref()
            .ok_or_else(|| err!(ESTALE, "TUF_NOT_REFRESHED"))?;
        check_expiry(&sn.0.signed.expires, now, Role::Snapshot)?;
        let tg = self
            .targets
            .as_ref()
            .ok_or_else(|| err!(ESTALE, "TUF_NOT_REFRESHED"))?;
        check_expiry(&tg.0.signed.expires, now, Role::Targets)
    }

    /// Earliest exclusive expiry of the complete adopted metadata chain. This
    /// small bound can be checked at a serialized release without cloning or
    /// verifying metadata while holding that release lock.
    pub fn fresh_until(&self) -> EnclaveResult<i64> {
        let timestamp = self
            .timestamp
            .as_ref()
            .ok_or_else(|| err!(ESTALE, "TUF_NOT_REFRESHED"))?;
        let snapshot = self
            .snapshot
            .as_ref()
            .ok_or_else(|| err!(ESTALE, "TUF_NOT_REFRESHED"))?;
        let targets = self
            .targets
            .as_ref()
            .ok_or_else(|| err!(ESTALE, "TUF_NOT_REFRESHED"))?;
        [
            &self.root.signed.expires,
            &timestamp.0.signed.expires,
            &snapshot.0.signed.expires,
            &targets.0.signed.expires,
        ]
        .into_iter()
        .map(|expiry| parse_rfc3339_utc(expiry).ok_or_else(|| err!(EINVAL, "TUF_BAD_EXPIRES")))
        .try_fold(i64::MAX, |earliest, expiry| {
            expiry.map(|expiry| earliest.min(expiry))
        })
    }

    /// Versions `(timestamp, snapshot, targets)`.
    pub fn versions(&self) -> (u64, u64, u64) {
        (
            self.timestamp.as_ref().map_or(0, |t| t.0.signed.version),
            self.snapshot.as_ref().map_or(0, |t| t.0.signed.version),
            self.targets.as_ref().map_or(0, |t| t.0.signed.version),
        )
    }

    /// Timestamp `version` and the BLAKE3 of the trusted snapshot bytes.
    pub fn snapshot_root_blake3(&self) -> Option<[u8; 32]> {
        self.snapshot
            .as_ref()
            .map(|(_, b)| *blake3::hash(b).as_bytes())
    }

    /// Look up a target (requires fresh metadata).
    pub fn target(&self, name: &str, now: i64) -> EnclaveResult<&TargetFile> {
        self.ensure_fresh(now)?;
        let (t, _) = self
            .targets
            .as_ref()
            .ok_or_else(|| err!(ESTALE, "TUF_NOT_REFRESHED"))?;
        t.signed
            .targets
            .get(name)
            .ok_or_else(|| err!(EACCES, "TUF_UNKNOWN_TARGET", "{name}"))
    }

    /// All trusted targets.
    pub fn targets(&self) -> Option<&BTreeMap<String, TargetFile>> {
        self.targets.as_ref().map(|t| &t.0.signed.targets)
    }

    /// Verify downloaded target bytes against length + both hashes.
    pub fn verify_target(&self, name: &str, bytes: &[u8], now: i64) -> EnclaveResult<&TargetFile> {
        let tf = self.target(name, now)?;
        if tf.length != bytes.len() as u64 {
            fail!(EACCES, "TUF_TARGET_LENGTH");
        }
        if tf.hashes.get("sha256") != Some(&hex::encode(Sha256::digest(bytes))) {
            fail!(EACCES, "TUF_TARGET_SHA256");
        }
        if tf.hashes.get("blake3") != Some(&blake3::hash(bytes).to_hex().to_string()) {
            fail!(EACCES, "TUF_TARGET_BLAKE3");
        }
        Ok(tf)
    }

    /// Verify a delegated targets metadata file for `role_name` against the
    /// delegations in the trusted top-level `targets.json`.
    pub fn verify_delegated_targets(
        &self,
        role_name: &str,
        bytes: &[u8],
        now: Option<i64>,
    ) -> EnclaveResult<Signed<TargetsMeta>> {
        let (top_targets, _) = self
            .targets
            .as_ref()
            .ok_or_else(|| err!(EPERM, "TUF_ORDER", "top-level targets first"))?;
        let delegations = top_targets
            .signed
            .delegations
            .as_ref()
            .ok_or_else(|| err!(EINVAL, "TUF_NO_DELEGATIONS", "targets has no delegations"))?;
        let roles = delegations
            .roles
            .as_ref()
            .ok_or_else(|| err!(EINVAL, "TUF_NO_DELEGATED_ROLES", "delegations has no roles"))?;
        let role = roles
            .iter()
            .find(|r| r.name == role_name)
            .ok_or_else(|| err!(EACCES, "TUF_DELEGATED_ROLE_NOT_FOUND", "{role_name}"))?;

        let del_targets: Signed<TargetsMeta> = parse(bytes)?;
        check_type(&del_targets.signed._type, "targets")?;

        let msg = crate::canonical_json::to_canonical_json_bytes(&del_targets.signed)?;
        let mut good: BTreeSet<&str> = BTreeSet::new();
        for sig in &del_targets.signatures {
            if !role.keyids.iter().any(|k| k == &sig.keyid) || good.contains(sig.keyid.as_str()) {
                continue;
            }
            let Some(key) = delegations.keys.get(&sig.keyid) else {
                continue;
            };
            if key.keyid().ok().as_deref() != Some(sig.keyid.as_str()) {
                continue;
            }
            let Some(vk) = key.verifying_key() else {
                continue;
            };
            let Ok(raw) = hex::decode(&sig.sig) else {
                continue;
            };
            let Ok(sg) = Signature::from_slice(&raw) else {
                continue;
            };
            if vk.verify_strict(&msg, &sg).is_ok() {
                good.insert(sig.keyid.as_str());
            }
        }
        if (good.len() as u32) < role.threshold {
            fail!(
                EACCES,
                "TUF_THRESHOLD_NOT_MET",
                "delegated {}: {} of {}",
                role_name,
                good.len(),
                role.threshold
            );
        }

        for target_name in del_targets.signed.targets.keys() {
            if !role.matches_target(target_name) {
                fail!(
                    EACCES,
                    "TUF_DELEGATED_PATH_MISMATCH",
                    "target {target_name} not authorized for role {role_name}"
                );
            }
        }

        if let Some(now) = now {
            check_expiry(&del_targets.signed.expires, now, Role::Targets)?;
        }

        Ok(del_targets)
    }
}

/// Test/dev repository builder: keys per role + metadata emission.
#[derive(Debug)]
pub struct RepoBuilder {
    /// Keys per role.
    pub keys: BTreeMap<Role, Vec<SigningKey>>,
    /// Thresholds per role.
    pub thresholds: BTreeMap<Role, u32>,
    /// Root version.
    pub root_version: u64,
}

impl RepoBuilder {
    /// `n` keys per role with threshold `k`.
    pub fn new(n: usize, k: u32) -> Self {
        let mut keys = BTreeMap::new();
        let mut thresholds = BTreeMap::new();
        for r in [Role::Root, Role::Timestamp, Role::Snapshot, Role::Targets] {
            keys.insert(
                r,
                (0..n)
                    .map(|_| SigningKey::generate(&mut rand_core::OsRng))
                    .collect(),
            );
            thresholds.insert(r, k);
        }
        Self {
            keys,
            thresholds,
            root_version: 1,
        }
    }

    /// Root body.
    pub fn root_body(&self, expires: &str) -> EnclaveResult<RootMeta> {
        let mut keys = BTreeMap::new();
        let mut roles = BTreeMap::new();
        for (r, ks) in &self.keys {
            let mut ids = Vec::new();
            for k in ks {
                let tk = TufKey::ed25519(&k.verifying_key());
                let id = tk.keyid()?;
                keys.insert(id.clone(), tk);
                ids.push(id);
            }
            roles.insert(
                r.name().to_owned(),
                RoleKeys {
                    keyids: ids,
                    threshold: self.thresholds[r],
                },
            );
        }
        Ok(RootMeta {
            _type: "root".into(),
            spec_version: SPEC_VERSION.into(),
            version: self.root_version,
            expires: expires.into(),
            keys,
            roles,
            consistent_snapshot: false,
        })
    }

    fn signers(&self, r: Role) -> Vec<&SigningKey> {
        self.keys[&r]
            .iter()
            .take(self.thresholds[&r] as usize)
            .collect()
    }

    /// Signed root bytes.
    pub fn root(&self, expires: &str) -> EnclaveResult<Vec<u8>> {
        let body = self.root_body(expires)?;
        to_bytes(&sign(&body, &self.signers(Role::Root))?)
    }

    /// Signed targets bytes.
    pub fn targets(
        &self,
        version: u64,
        expires: &str,
        targets: BTreeMap<String, TargetFile>,
    ) -> EnclaveResult<Vec<u8>> {
        self.targets_with_delegations(version, expires, targets, None)
    }

    /// Signed targets bytes with optional delegations.
    pub fn targets_with_delegations(
        &self,
        version: u64,
        expires: &str,
        targets: BTreeMap<String, TargetFile>,
        delegations: Option<Delegations>,
    ) -> EnclaveResult<Vec<u8>> {
        let body = TargetsMeta {
            _type: "targets".into(),
            spec_version: SPEC_VERSION.into(),
            version,
            expires: expires.into(),
            targets,
            delegations,
        };
        to_bytes(&sign(&body, &self.signers(Role::Targets))?)
    }

    /// Signed snapshot bytes referencing `targets_bytes`.
    pub fn snapshot(
        &self,
        version: u64,
        expires: &str,
        targets_version: u64,
        targets_bytes: &[u8],
    ) -> EnclaveResult<Vec<u8>> {
        let mut meta = BTreeMap::new();
        meta.insert(
            "targets.json".to_owned(),
            meta_file(targets_version, targets_bytes),
        );
        let body = MetaListing {
            _type: "snapshot".into(),
            spec_version: SPEC_VERSION.into(),
            version,
            expires: expires.into(),
            meta,
        };
        to_bytes(&sign(&body, &self.signers(Role::Snapshot))?)
    }

    /// Signed timestamp bytes referencing `snapshot_bytes`.
    pub fn timestamp(
        &self,
        version: u64,
        expires: &str,
        snapshot_version: u64,
        snapshot_bytes: &[u8],
    ) -> EnclaveResult<Vec<u8>> {
        let mut meta = BTreeMap::new();
        meta.insert(
            "snapshot.json".to_owned(),
            meta_file(snapshot_version, snapshot_bytes),
        );
        let body = MetaListing {
            _type: "timestamp".into(),
            spec_version: SPEC_VERSION.into(),
            version,
            expires: expires.into(),
            meta,
        };
        to_bytes(&sign(&body, &self.signers(Role::Timestamp))?)
    }
}

/// `MetaFile` with length + dual hashes.
pub fn meta_file(version: u64, bytes: &[u8]) -> MetaFile {
    let mut h = BTreeMap::new();
    h.insert("sha256".to_owned(), hex::encode(Sha256::digest(bytes)));
    h.insert(
        "blake3".to_owned(),
        blake3::hash(bytes).to_hex().to_string(),
    );
    MetaFile {
        version,
        length: Some(bytes.len() as u64),
        hashes: Some(h),
    }
}

/// Target entry with dual hashes.
pub fn target_file(bytes: &[u8], custom: Option<Value>) -> TargetFile {
    let mut h = BTreeMap::new();
    h.insert("sha256".to_owned(), hex::encode(Sha256::digest(bytes)));
    h.insert(
        "blake3".to_owned(),
        blake3::hash(bytes).to_hex().to_string(),
    );
    TargetFile {
        length: bytes.len() as u64,
        hashes: h,
        custom,
    }
}

/// Serialize signed metadata to JSON bytes.
pub fn to_bytes<T: Serialize>(s: &Signed<T>) -> EnclaveResult<Vec<u8>> {
    serde_json::to_vec_pretty(s).map_err(|e| err!(EINVAL, "TUF_ENCODE", "{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXP: &str = "2030-01-01T00:00:00Z";
    const NOW: i64 = 1_793_884_860; // 2026-11-05

    fn repo_with(
        target_bytes: &[u8],
        tv: u64,
        sv: u64,
        tsv: u64,
    ) -> (RepoBuilder, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let r = RepoBuilder::new(3, 2);
        let root = r.root(EXP).unwrap();
        let mut t = BTreeMap::new();
        t.insert(
            "model.safetensors".to_owned(),
            target_file(target_bytes, None),
        );
        let targets = r.targets(tv, EXP, t).unwrap();
        let snap = r.snapshot(sv, EXP, tv, &targets).unwrap();
        let ts = r.timestamp(tsv, EXP, sv, &snap).unwrap();
        (r, root, ts, snap, targets)
    }

    #[test]
    fn happy_path_and_target_verification() {
        let (_r, root, ts, snap, targets) = repo_with(b"weights", 1, 1, 1);
        let mut c = TufClient::bootstrap(&root).unwrap();
        c.refresh(&ts, &snap, &targets, NOW).unwrap();
        c.verify_target("model.safetensors", b"weights", NOW)
            .unwrap();
        assert!(c
            .verify_target("model.safetensors", b"weightz", NOW)
            .unwrap_err()
            .is("TUF_TARGET_SHA256"));
        assert!(c.target("other", NOW).unwrap_err().is("TUF_UNKNOWN_TARGET"));
    }

    #[test]
    fn exported_state_restores_as_a_rollback_floor() {
        let (r, root, ts, snap, targets) = repo_with(b"v7", 7, 7, 7);
        let mut c = TufClient::bootstrap(&root).unwrap();
        c.refresh(&ts, &snap, &targets, NOW).unwrap();
        let st = c.export().unwrap();
        // Restored state keeps the versions, even after the metadata expired.
        let mut back = TufClient::restore(&st).unwrap();
        assert_eq!(back.versions(), (7, 7, 7));
        assert!(back.chain_contains(&root));
        assert!(back
            .ensure_fresh(1_900_000_000)
            .unwrap_err()
            .is("TUF_METADATA_EXPIRED"));
        // A validly signed older repository is a rollback for the restored client.
        let mut t = BTreeMap::new();
        t.insert("model.safetensors".to_owned(), target_file(b"v5", None));
        let t5 = r.targets(5, EXP, t).unwrap();
        let s5 = r.snapshot(5, EXP, 5, &t5).unwrap();
        let ts5 = r.timestamp(5, EXP, 5, &s5).unwrap();
        assert!(back
            .refresh(&ts5, &s5, &t5, NOW)
            .unwrap_err()
            .is("TUF_ROLLBACK"));
        // Stored metadata is re-verified, not trusted: a swapped snapshot fails.
        let mut bad = st.clone();
        bad.snapshot = Some(String::from_utf8(s5).unwrap());
        assert!(TufClient::restore(&bad).is_err());
    }

    #[test]
    fn resumed_clock_never_starts_below_the_high_water_mark() {
        let mut c = TrustedClock::resumed(NOW - 86_400, NOW);
        assert!(c.now(NOW - 86_400) >= NOW);
        assert!(c.high_water() >= NOW);
        let mut c = TrustedClock::resumed(NOW + 10, NOW);
        assert!(c.now(NOW) >= NOW + 10);
    }

    #[test]
    fn threshold_enforced() {
        let r = RepoBuilder::new(3, 2);
        let body = r.root_body(EXP).unwrap();
        let one = to_bytes(&sign(&body, &[&r.keys[&Role::Root][0]]).unwrap()).unwrap();
        assert!(TufClient::bootstrap(&one)
            .unwrap_err()
            .is("TUF_THRESHOLD_NOT_MET"));
        // Same key twice does not satisfy 2-of-3.
        let k = &r.keys[&Role::Root][0];
        let dup = to_bytes(&sign(&body, &[k, k]).unwrap()).unwrap();
        assert!(TufClient::bootstrap(&dup).is_err());
    }

    #[test]
    fn rollback_freeze_and_mix_and_match_rejected() {
        let (r, root, ts, snap, targets) = repo_with(b"v2", 2, 2, 2);
        let mut c = TufClient::bootstrap(&root).unwrap();
        c.refresh(&ts, &snap, &targets, NOW).unwrap();
        // Rollback: older timestamp.
        let mut t = BTreeMap::new();
        t.insert("model.safetensors".to_owned(), target_file(b"v1", None));
        let old_targets = r.targets(1, EXP, t).unwrap();
        let old_snap = r.snapshot(1, EXP, 1, &old_targets).unwrap();
        let old_ts = r.timestamp(1, EXP, 1, &old_snap).unwrap();
        assert!(c
            .refresh(&old_ts, &old_snap, &old_targets, NOW)
            .unwrap_err()
            .is("TUF_ROLLBACK"));
        // Freeze: expired timestamp.
        let frozen_ts = r.timestamp(3, "2026-01-01T00:00:00Z", 2, &snap).unwrap();
        assert!(c
            .refresh(&frozen_ts, &snap, &targets, NOW)
            .unwrap_err()
            .is("TUF_METADATA_EXPIRED"));
        // Mix-and-match: new snapshot pins targets v3, attacker serves targets v2.
        let mut t3 = BTreeMap::new();
        t3.insert("model.safetensors".to_owned(), target_file(b"v3", None));
        let targets3 = r.targets(3, EXP, t3).unwrap();
        let snap3 = r.snapshot(3, EXP, 3, &targets3).unwrap();
        let ts3 = r.timestamp(3, EXP, 3, &snap3).unwrap();
        let e = c.refresh(&ts3, &snap3, &targets, NOW).unwrap_err();
        assert!(
            e.is("TUF_LENGTH_MISMATCH")
                || e.is("TUF_HASH_MISMATCH")
                || e.is("TUF_TARGETS_VERSION_MISMATCH"),
            "{e}"
        );
        // Failed refresh left state untouched.
        assert_eq!(c.versions(), (2, 2, 2));
        c.refresh(&ts3, &snap3, &targets3, NOW).unwrap();
        assert_eq!(c.versions(), (3, 3, 3));
        // Equivocation: same version, different content.
        let ts3b = r.timestamp(3, "2031-01-01T00:00:00Z", 3, &snap3).unwrap();
        assert!(c
            .update_timestamp(&ts3b, NOW)
            .unwrap_err()
            .is("TUF_EQUIVOCATION"));
        // Freshness on use.
        assert!(c
            .target("model.safetensors", 1_900_000_000)
            .unwrap_err()
            .is("TUF_METADATA_EXPIRED"));
    }

    #[test]
    fn root_rotation_requires_old_and_new_thresholds() {
        let mut r = RepoBuilder::new(2, 1);
        let root1 = r.root(EXP).unwrap();
        let mut c = TufClient::bootstrap(&root1).unwrap();
        let old_keys = r.keys[&Role::Root].clone();
        // New root keys, signed only by the new keys: rejected.
        r.keys.insert(
            Role::Root,
            vec![SigningKey::generate(&mut rand_core::OsRng)],
        );
        r.root_version = 2;
        let body2 = r.root_body(EXP).unwrap();
        let only_new = to_bytes(&sign(&body2, &[&r.keys[&Role::Root][0]]).unwrap()).unwrap();
        assert!(c
            .update_root(&only_new)
            .unwrap_err()
            .is("TUF_THRESHOLD_NOT_MET"));
        let both =
            to_bytes(&sign(&body2, &[&old_keys[0], &r.keys[&Role::Root][0]]).unwrap()).unwrap();
        c.update_root(&both).unwrap();
        assert_eq!(c.root().version, 2);
        // Skipping a version is rejected.
        r.root_version = 4;
        let body4 = r.root_body(EXP).unwrap();
        let skip = to_bytes(&sign(&body4, &[&r.keys[&Role::Root][0]]).unwrap()).unwrap();
        assert!(c.update_root(&skip).unwrap_err().is("TUF_ROOT_VERSION"));
    }

    #[test]
    fn trusted_clock_never_goes_backwards() {
        let mut clk = TrustedClock::anchored(NOW);
        assert!(clk.now(NOW - 10_000) >= NOW);
        assert!(clk.now(NOW + 50) >= NOW + 50);
        assert!(clk.now(NOW) >= NOW + 50);
    }

    fn sign_legacy_jcs<T: Serialize + Clone>(
        body: &T,
        keys: &[&SigningKey],
    ) -> EnclaveResult<Signed<T>> {
        let msg = enclave_core::jcs::to_jcs_bytes(body)?;
        let mut sigs = Vec::new();
        for k in keys {
            let keyid = TufKey::ed25519(&k.verifying_key()).legacy_jcs_keyid()?;
            sigs.push(TufSignature {
                keyid,
                sig: hex::encode(k.sign(&msg).to_bytes()),
            });
        }
        Ok(Signed {
            signed: body.clone(),
            signatures: sigs,
        })
    }

    #[test]
    fn legacy_jcs_signed_root_is_rejected_with_canonicalisation_legacy() {
        let r = RepoBuilder::new(3, 2);
        let mut keys = BTreeMap::new();
        let mut roles = BTreeMap::new();
        for (role, ks) in &r.keys {
            let mut ids = Vec::new();
            for k in ks {
                let tk = TufKey::ed25519(&k.verifying_key());
                let id = tk.legacy_jcs_keyid().unwrap();
                keys.insert(id.clone(), tk);
                ids.push(id);
            }
            roles.insert(
                role.name().to_owned(),
                RoleKeys {
                    keyids: ids,
                    threshold: r.thresholds[role],
                },
            );
        }
        let legacy_root_body = RootMeta {
            _type: "root".into(),
            spec_version: "1.0.31\nlegacy".into(),
            version: 1,
            expires: EXP.into(),
            keys,
            roles,
            consistent_snapshot: false,
        };
        let signers: Vec<&SigningKey> = r.keys[&Role::Root].iter().take(2).collect();
        let signed = sign_legacy_jcs(&legacy_root_body, &signers).unwrap();
        let legacy_bytes = to_bytes(&signed).unwrap();

        let err = TufClient::bootstrap(&legacy_bytes).unwrap_err();
        assert!(
            err.is("TUF_CANONICALISATION_LEGACY"),
            "expected TUF_CANONICALISATION_LEGACY, got: {err}"
        );
    }
}
