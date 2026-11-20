//! Cloudflare R2 / ORAS over OCI v1.1 artifact transport (FS-702 §3.3, D-19d).
//!
//! Conforms to OCI Distribution & Artifact Specification v1.1:
//! - Manifest fetch: `GET /v2/<name>/manifests/<reference>`
//! - Blob fetch: `GET /v2/<name>/blobs/<digest>`
//! - Supports HTTP Range requests for partial/slice fetching.
//! - Credentials strictly from host config or files owned by `_enclavecas`.

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::net::TcpStream;

/// OCI content descriptor (OCI Image Spec v1.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Descriptor {
    /// Layer MIME media type.
    #[serde(rename = "mediaType")]
    pub media_type: String,
    /// Cryptographic digest (e.g. sha256:<hex>).
    pub digest: String,
    /// Layer byte size.
    pub size: u64,
    /// Optional remote download URLs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urls: Option<Vec<String>>,
    /// Custom metadata annotations.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

/// OCI artifact / image manifest (OCI Image Spec v1.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciManifest {
    /// Manifest schema version (always 2).
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    /// Optional manifest media type.
    #[serde(rename = "mediaType", default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    /// Optional artifact media type.
    #[serde(
        rename = "artifactType",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub artifact_type: Option<String>,
    /// Ordered content layers.
    #[serde(default)]
    pub layers: Vec<Descriptor>,
    /// Artifact annotations.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

/// Client configuration for R2 / ORAS distribution.
#[derive(Debug, Clone)]
pub struct OrasConfig {
    /// Host address / host:port (e.g. "127.0.0.1:8443" or "r2.enterprise.enclave:443").
    pub host: String,
    /// Bearer authentication token from host config.
    pub bearer_token: Option<String>,
    /// Base repository path (e.g. "models/internal").
    pub repository: String,
}

/// ORAS client speaking OCI Distribution Spec v1.1.
#[derive(Debug, Clone)]
pub struct OrasClient {
    /// Client configuration.
    pub config: OrasConfig,
}

impl OrasClient {
    /// Create new ORAS client.
    pub fn new(config: OrasConfig) -> Self {
        Self { config }
    }

    /// Perform raw HTTP request to the OCI registry over TCP stream.
    fn http_get(
        &self,
        stream: &mut TcpStream,
        path: &str,
        headers: &[(&str, &str)],
    ) -> EnclaveResult<(u16, BTreeMap<String, String>, Vec<u8>)> {
        if path.contains('\r')
            || path.contains('\n')
            || self.config.host.contains('\r')
            || self.config.host.contains('\n')
        {
            fail!(EINVAL, "ORAS_CRLF_INJECTION");
        }

        if self.config.bearer_token.is_some()
            && !self.config.host.starts_with("127.0.0.1")
            && !self.config.host.starts_with("localhost")
            && !self.config.host.starts_with("[::1]")
        {
            fail!(
                EPERM,
                "CLEARTEXT_TOKEN_FORBIDDEN",
                "bearer token transmission requires TLS encrypted channel on remote host"
            );
        }

        let mut req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            path, self.config.host
        );
        if let Some(token) = &self.config.bearer_token {
            req.push_str(&format!("Authorization: Bearer {}\r\n", token));
        }
        for (k, v) in headers {
            req.push_str(&format!("{}: {}\r\n", k, v));
        }
        req.push_str("\r\n");

        stream
            .write_all(req.as_bytes())
            .map_err(|e| err!(EIO, "ORAS_WRITE", "{e}"))?;
        stream.flush().map_err(|e| err!(EIO, "ORAS_FLUSH", "{e}"))?;

        let mut resp_bytes = Vec::new();
        use std::io::Read;
        stream
            .take(512 * 1024 * 1024)
            .read_to_end(&mut resp_bytes)
            .map_err(|e| err!(EIO, "ORAS_READ", "{e}"))?;

        let sep = b"\r\n\r\n";
        let sep_pos = resp_bytes
            .windows(4)
            .position(|w| w == sep)
            .ok_or_else(|| err!(EIO, "ORAS_PARSE", "missing HTTP header separator"))?;

        let header_str = std::str::from_utf8(&resp_bytes[..sep_pos])
            .map_err(|e| err!(EIO, "ORAS_HEADER_UTF8", "{e}"))?;
        let body = resp_bytes[sep_pos + 4..].to_vec();

        let mut lines = header_str.lines();
        let status_line = lines.next().ok_or_else(|| err!(EIO, "ORAS_EMPTY_STATUS"))?;
        let mut parts = status_line.split_whitespace();
        let _http_ver = parts.next();
        let status_code: u16 = parts
            .next()
            .and_then(|c| c.parse().ok())
            .ok_or_else(|| err!(EIO, "ORAS_BAD_STATUS", "{status_line}"))?;

        let mut resp_headers = BTreeMap::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                resp_headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }

        Ok((status_code, resp_headers, body))
    }

    /// Fetch and parse an OCI manifest by reference (tag or digest).
    pub fn fetch_manifest(
        &self,
        stream: &mut TcpStream,
        reference: &str,
    ) -> EnclaveResult<OciManifest> {
        let path = format!("/v2/{}/manifests/{}", self.config.repository, reference);
        let accept = "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.artifact.manifest.v1+json";
        let (status, _headers, body) = self.http_get(stream, &path, &[("Accept", accept)])?;
        if status != 200 {
            fail!(EACCES, "ORAS_MANIFEST_FETCH_FAILED", "status: {status}");
        }
        let manifest: OciManifest = serde_json::from_slice(&body)
            .map_err(|e| err!(EINVAL, "ORAS_MANIFEST_PARSE", "{e}"))?;
        Ok(manifest)
    }

    /// Fetch a full OCI blob by digest.
    pub fn fetch_blob(&self, stream: &mut TcpStream, digest: &str) -> EnclaveResult<Vec<u8>> {
        let path = format!("/v2/{}/blobs/{}", self.config.repository, digest);
        let (status, _headers, body) = self.http_get(stream, &path, &[])?;
        if status != 200 {
            fail!(EACCES, "ORAS_BLOB_FETCH_FAILED", "status: {status}");
        }
        if let Some((algo, expected_hex)) = digest.split_once(':') {
            if algo == "sha256" {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&body);
                let actual_hex = hex::encode(hasher.finalize());
                if actual_hex != expected_hex {
                    fail!(
                        EACCES,
                        "ORAS_BLOB_DIGEST_MISMATCH",
                        "digest {actual_hex} != expected {expected_hex}"
                    );
                }
            }
        }
        Ok(body)
    }

    /// Fetch a byte range of an OCI blob.
    pub fn fetch_blob_range(
        &self,
        stream: &mut TcpStream,
        digest: &str,
        start: u64,
        end: u64,
    ) -> EnclaveResult<Vec<u8>> {
        let path = format!("/v2/{}/blobs/{}", self.config.repository, digest);
        let range_header = format!("bytes={}-{}", start, end);
        let (status, _headers, body) = self.http_get(stream, &path, &[("Range", &range_header)])?;
        if status != 206 && status != 200 {
            fail!(EACCES, "ORAS_BLOB_RANGE_FAILED", "status: {status}");
        }
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn test_oci_manifest_serde() {
        let json_raw = r#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "artifactType": "application/vnd.enclave.model.v1",
            "layers": [
                {
                    "mediaType": "application/vnd.enclave.layer.v1+safetensors",
                    "digest": "sha256:7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a",
                    "size": 1048576,
                    "annotations": {
                        "org.enclave.bao.root": "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b"
                    }
                }
            ],
            "annotations": {
                "org.opencontainers.image.created": "2026-11-06T12:00:00Z"
            }
        }"#;

        let manifest: OciManifest = serde_json::from_str(json_raw).expect("parse manifest");
        assert_eq!(manifest.schema_version, 2);
        assert_eq!(manifest.layers.len(), 1);
        assert_eq!(manifest.layers[0].size, 1048576);
        assert_eq!(
            manifest.layers[0]
                .annotations
                .get("org.enclave.bao.root")
                .unwrap(),
            "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b"
        );
    }

    #[test]
    fn test_oras_mock_server_fetch() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().unwrap();

        let handle = thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 1024];
            let n = socket.read(&mut buf).unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);

            if req.contains("/v2/models/internal/manifests/v1.0") {
                let body = r#"{"schemaVersion":2,"layers":[]}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                socket.write_all(resp.as_bytes()).unwrap();
            }
        });

        let config = OrasConfig {
            host: addr.to_string(),
            bearer_token: Some("secret-token-123".into()),
            repository: "models/internal".into(),
        };
        let client = OrasClient::new(config);

        let mut stream = TcpStream::connect(addr).expect("connect");
        let manifest = client
            .fetch_manifest(&mut stream, "v1.0")
            .expect("fetch manifest");
        assert_eq!(manifest.schema_version, 2);

        handle.join().unwrap();
    }
}
