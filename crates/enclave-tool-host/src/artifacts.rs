//! Independently signed offline native-artifact authority (F100).
//!
//! Requests select a target, never a path, digest, signing key or native bytes.
//! Verified artifacts are copied into an immutable in-memory table before use.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};

use crate::lifecycle::{trusted_unix_ns, DispatchExpiry};
use crate::ticket::RowFormat;
use crate::{DurableToolHost, ExecutionTicket, ToolOutput};

#[path = "artifact_argument_owner.rs"]
mod argument_owner;

const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_MANIFEST: usize = 1024 * 1024;

/// One offline-built module and its output metadata, signed by the build authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedModuleV1 {
    /// depot server target.
    pub server: String,
    /// depot tool target.
    pub tool_name: String,
    /// A single filename within the independently configured artifact directory.
    pub file_name: String,
    /// Digest computed by the trusted offline compiler, never by the request.
    pub module_blake3: [u8; 32],
    /// Actual tools/list, checked again against the runtime lock before publication.
    pub tools_list: serde_json::Value,
    /// Output row contract.
    pub row_format: RowFormat,
    /// Build authority's upper bound; runtime policy may impose a smaller bound.
    pub max_rows: u64,
}

/// Versioned, expiring build registry; the verification key is configured separately.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactManifestV1 {
    /// Must equal one.
    pub v: u8,
    /// UNIX nanoseconds, signed.
    pub issued_at_unix_ns: u64,
    /// UNIX nanoseconds, signed and checked on load and every dispatch.
    pub expires_at_unix_ns: u64,
    /// Bounded immutable target table.
    pub modules: Vec<ApprovedModuleV1>,
}

impl ArtifactManifestV1 {
    /// Domain-separated typed JSON bytes for the trusted offline build signer.
    /// The fixed struct field order and ordered JSON maps are deterministic;
    /// integer nanoseconds retain all 64 bits instead of passing through f64/JCS.
    pub fn signing_bytes(&self) -> EnclaveResult<Vec<u8>> {
        let mut bytes = b"depot-OFFLINE-TOOL-MANIFEST-V1\0".to_vec();
        bytes.extend_from_slice(
            &serde_json::to_vec(self).map_err(|_| err!(EINVAL, "TOOL_MANIFEST_SERIALIZE"))?,
        );
        Ok(bytes)
    }
    fn check_time(&self, now: u64) -> EnclaveResult<()> {
        if self.v != 1
            || self.issued_at_unix_ns > now
            || now > self.expires_at_unix_ns
            || self.expires_at_unix_ns <= self.issued_at_unix_ns
        {
            fail!(EACCES, "TOOL_MANIFEST_TIME_OR_VERSION");
        }
        Ok(())
    }
}

/// Signed registry envelope. Its embedded fields cannot select its trust key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedArtifactManifestV1 {
    /// Signed authority statement.
    pub manifest: ArtifactManifestV1,
    /// Hex Ed25519 signature over the versioned domain and typed JSON manifest.
    pub signature: String,
}

#[derive(Debug)]
struct Artifact {
    spec: ApprovedModuleV1,
    bytes: Vec<u8>,
}

/// Verified immutable artifact snapshots. Construction checks signature and every
/// digest without deserializing any native code. The caller supplies an independent
/// trusted build key and directory, not fields taken from a plan/request.
#[derive(Debug)]
pub struct TrustedArtifactTable {
    manifest: ArtifactManifestV1,
    entries: BTreeMap<(String, String), Artifact>,
    build_key: VerifyingKey,
    metadata_verified: bool,
}

impl TrustedArtifactTable {
    /// Validate every signed tools/list against the runtime's independently loaded
    /// lock before allowing side effects, in addition to output-ingress checks.
    pub fn verify_tools_lists<F>(&mut self, mut verify: F) -> EnclaveResult<()>
    where
        F: FnMut(&str, &serde_json::Value) -> EnclaveResult<()>,
    {
        self.metadata_verified = false;
        for entry in self.entries.values() {
            verify(&entry.spec.server, &entry.spec.tools_list)?;
        }
        self.metadata_verified = true;
        Ok(())
    }

    /// Load a signed manifest and exact artifact snapshots; refuses partial tables.
    pub fn load(bytes: &[u8], build_key: &VerifyingKey, directory: &Path) -> EnclaveResult<Self> {
        if bytes.len() > MAX_MANIFEST {
            fail!(E2BIG, "TOOL_MANIFEST_LIMIT");
        }
        if !directory.is_absolute()
            || std::fs::canonicalize(directory)
                .map_err(|e| err!(EIO, "TOOL_ARTIFACT_DIRECTORY", "{e}"))?
                != directory
        {
            fail!(EACCES, "TOOL_ARTIFACT_DIRECTORY");
        }
        let signed: SignedArtifactManifestV1 = serde_json::from_slice(bytes)
            .map_err(|e| err!(EINVAL, "TOOL_MANIFEST_PARSE", "{e}"))?;
        let sig =
            hex::decode(&signed.signature).map_err(|_| err!(EINVAL, "TOOL_MANIFEST_SIGNATURE"))?;
        let sig =
            Signature::from_slice(&sig).map_err(|_| err!(EINVAL, "TOOL_MANIFEST_SIGNATURE"))?;
        build_key
            .verify(&signed.manifest.signing_bytes()?, &sig)
            .map_err(|_| err!(EACCES, "TOOL_MANIFEST_UNTRUSTED"))?;
        signed.manifest.check_time(trusted_unix_ns()?)?;
        if signed.manifest.modules.is_empty() || signed.manifest.modules.len() > 8 {
            fail!(E2BIG, "TOOL_MANIFEST_COUNT");
        }
        let mut entries = BTreeMap::new();
        let mut total = 0usize;
        for spec in &signed.manifest.modules {
            if spec.server.is_empty()
                || spec.server.len() > 256
                || spec.tool_name.is_empty()
                || spec.tool_name.len() > 256
                || spec.max_rows == 0
                || spec.file_name.is_empty()
                || spec.file_name.len() > 128
                || spec.file_name.starts_with('.')
                || !spec
                    .file_name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            {
                fail!(EINVAL, "TOOL_MANIFEST_TARGET");
            }
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(directory.join(&spec.file_name))
                .map_err(|e| err!(EIO, "TOOL_ARTIFACT_OPEN", "{e}"))?;
            let meta = file
                .metadata()
                .map_err(|e| err!(EIO, "TOOL_ARTIFACT_STAT", "{e}"))?;
            if !meta.is_file() || meta.len() > MAX_BYTES as u64 {
                fail!(E2BIG, "TOOL_ARTIFACT_LIMIT");
            }
            let mut snapshot = Vec::new();
            Read::by_ref(&mut file)
                .take((MAX_BYTES + 1) as u64)
                .read_to_end(&mut snapshot)
                .map_err(|e| err!(EIO, "TOOL_ARTIFACT_READ", "{e}"))?;
            total = total
                .checked_add(snapshot.len())
                .ok_or_else(|| err!(E2BIG, "TOOL_ARTIFACT_LIMIT"))?;
            if snapshot.len() > MAX_BYTES || total > MAX_BYTES {
                fail!(E2BIG, "TOOL_ARTIFACT_LIMIT");
            }
            if blake3::hash(&snapshot).as_bytes() != &spec.module_blake3 {
                fail!(EACCES, "TOOL_ARTIFACT_DIGEST");
            }
            let target = (spec.server.clone(), spec.tool_name.clone());
            if entries
                .insert(
                    target,
                    Artifact {
                        spec: spec.clone(),
                        bytes: snapshot,
                    },
                )
                .is_some()
            {
                fail!(EINVAL, "TOOL_MANIFEST_DUPLICATE");
            }
        }
        Ok(Self {
            manifest: signed.manifest,
            entries,
            build_key: *build_key,
            metadata_verified: false,
        })
    }
}

/// Trusted issuer/dispatcher: consumes only runtime-authorized targets and exact
/// arguments. The build authority key is distinct from the live ticket issuer.
pub struct ArtifactDispatcher {
    table: TrustedArtifactTable,
    host: DurableToolHost,
    issuer: SigningKey,
}
impl std::fmt::Debug for ArtifactDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArtifactDispatcher")
            .field("table", &self.table)
            .finish_non_exhaustive()
    }
}
impl ArtifactDispatcher {
    /// Reopen previously provisioned replay state. Never initializes missing state.
    pub fn open(
        table: TrustedArtifactTable,
        replay: &Path,
        issuer: SigningKey,
    ) -> EnclaveResult<Self> {
        if !table.metadata_verified {
            fail!(EACCES, "TOOL_METADATA_NOT_VERIFIED");
        }
        if table.build_key == issuer.verifying_key() {
            fail!(EACCES, "TOOL_BUILD_ISSUER_KEYS_NOT_DISTINCT");
        }
        let host = DurableToolHost::open(replay, issuer.verifying_key())?;
        Ok(Self {
            table,
            host,
            issuer,
        })
    }

    /// Execute the trusted table's exact target; no caller-supplied native bytes,
    /// paths, digests, row format or timestamps can enter this API. The runtime
    /// adapter must invoke it only after the live PDP accepts the call.
    pub fn execute(
        &self,
        server: &str,
        tool: &str,
        args_jcs: &[u8],
        row_bound: u64,
        authorization_id: &[u8; 32],
    ) -> EnclaveResult<(ToolOutput, String)> {
        self.execute_inner(server, tool, args_jcs, row_bound, authorization_id, None)
    }

    /// Apply the original custody endpoints to this already authorized call.
    /// These limits only shorten execution; they provide no factor or live fence.
    pub fn execute_before(&self, server: &str, tool: &str, args_jcs: &[u8],
        row_bound: u64, authorization_id: &[u8; 32], expiry: &DispatchExpiry)
        -> EnclaveResult<(ToolOutput, String)> {
        expiry.check()?;
        self.execute_inner(server, tool, args_jcs, row_bound, authorization_id, Some(expiry))
    }

    fn execute_inner(&self, server: &str, tool: &str, args_jcs: &[u8],
        row_bound: u64, authorization_id: &[u8; 32], expiry: Option<&DispatchExpiry>)
        -> EnclaveResult<(ToolOutput, String)> {
        let now = trusted_unix_ns()?;
        self.table.manifest.check_time(now)?;
        let entry = self
            .table
            .entries
            .get(&(server.to_owned(), tool.to_owned()))
            .ok_or_else(|| err!(EACCES, "TOOL_ARTIFACT_NOT_APPROVED"))?;
        if row_bound == 0 || row_bound > entry.spec.max_rows || args_jcs.len() > 1024 * 1024 {
            fail!(E2BIG, "TOOL_DISPATCH_LIMIT");
        }
        argument_owner::validate_private_arguments(args_jcs)?;
        let args_hash = blake3::hash(args_jcs).to_hex().to_string();
        // Parsing/hash work may have consumed the original lifetime. The real
        // bounded route never issues a replacement sixty-second authorization.
        let (now, ttl) = match expiry {
            Some(expiry) => expiry.ticket_window()?,
            None => (trusted_unix_ns()?, 60_000_000_000),
        };
        self.table.manifest.check_time(now)?;
        let ticket = ExecutionTicket::issue(
            &self.issuer,
            hex::encode(authorization_id),
            entry.spec.server.clone(),
            entry.spec.tool_name.clone(),
            args_hash,
            row_bound,
            now,
            ttl,
        )
        .for_module(&self.issuer, entry.spec.module_blake3)
        .with_row_format(&self.issuer, entry.spec.row_format);
        let output = match expiry {
            Some(expiry) => self.host.execute_cwasm_before(&ticket, &entry.spec.server,
                &entry.spec.tool_name, &entry.bytes, args_jcs, expiry)?,
            None => self.host.execute_cwasm(&ticket, &entry.spec.server,
                &entry.spec.tool_name, &entry.bytes, args_jcs)?,
        };
        let tools_list = serde_json::to_string(&entry.spec.tools_list)
            .map_err(|_| err!(EINVAL, "TOOL_LIST_JSON"))?;
        if let Some(expiry) = expiry { expiry.check()?; }
        Ok((output, tools_list))
    }
}

/// Sign an offline-built manifest. This helper belongs on the offline build host;
/// production request handlers never receive or use this build signing key.
pub fn sign_manifest(
    manifest: ArtifactManifestV1,
    key: &SigningKey,
) -> EnclaveResult<SignedArtifactManifestV1> {
    let signature = hex::encode(key.sign(&manifest.signing_bytes()?).to_bytes());
    Ok(SignedArtifactManifestV1 {
        manifest,
        signature,
    })
}
