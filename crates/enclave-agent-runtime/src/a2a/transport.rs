//! mTLS transport for cross-node A2A delegation (FS-704 §3.4, GAP-35, D-35a).
//!
//! Exposes `A2aClient` and `A2aServer` running over mutual TLS 1.3 with:
//! 1. Mandatory client and server X.509-SVID verification.
//! 2. RFC 9266 `EXPORTER-Channel-Binding` extraction (`[u8; 32]`).
//! 3. Bounded length-prefixed CBOR wire frames.
//! 4. Full integration with `Pdp::authorize` and `PeerCredentials::mtls`.

use std::sync::Arc;

use enclave_core::error::EnclaveResult;
use enclave_core::ipc::PeerCredentials;
use enclave_core::{err, fail};
use enclave_crypto::pop_biscuit::{PopBiscuitWireV1, Transport};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::a2a::spiffe::{SpiffeId, SpiffeSvid};
use crate::a2a::verifier::{extract_spiffe_id, SpiffeCertVerifier};
use crate::cedar_engine::ToolResource;
use crate::heap::CapabilityHeap;
use crate::pdp::{Pdp, ToolCallRequest};

/// Maximum frame size for A2A wire messages (64 KiB).
pub const MAX_A2A_FRAME_BYTES: usize = 65_536;

/// Configuration for an A2A mTLS client.
#[derive(Debug, Clone)]
pub struct A2aClientConfig {
    /// Client SVID.
    pub svid: SpiffeSvid,
    /// Expected server trust domain (e.g. `corporate.internal`).
    pub trust_domain: String,
    /// Trusted CA roots DER.
    pub ca_bundle_der: Vec<Vec<u8>>,
    /// Optional constraint to an exact expected server SPIFFE ID.
    pub expected_server_id: Option<SpiffeId>,
}

/// Configuration for an A2A mTLS server.
#[derive(Debug, Clone)]
pub struct A2aServerConfig {
    /// Server SVID.
    pub svid: SpiffeSvid,
    /// Expected client trust domain.
    pub trust_domain: String,
    /// Trusted CA roots DER.
    pub ca_bundle_der: Vec<Vec<u8>>,
    /// Optional constraint to an exact expected client SPIFFE ID.
    pub allowed_client_id: Option<SpiffeId>,
}

/// Request payload sent over an A2A mTLS channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2aRequest {
    /// The sender-constrained PoPBiscuitWireV1 frame.
    pub wire: PopBiscuitWireV1,
    /// Invoked tool name (e.g. `depot://cluster/query`).
    pub tool_name: String,
    /// Target namespace (e.g. `dev-billing`).
    pub target_namespace: String,
    /// JSON call arguments.
    pub args_json: String,
    /// Millibit slice requested for this call.
    pub qif_mb: i64,
}

impl A2aRequest {
    /// Encode as CBOR bytes.
    pub fn to_cbor(&self) -> EnclaveResult<Vec<u8>> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out).map_err(|e| err!(EINVAL, "CBOR_ENCODE", "{e}"))?;
        Ok(out)
    }

    /// Decode from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> EnclaveResult<Self> {
        if bytes.len() > MAX_A2A_FRAME_BYTES {
            fail!(E2BIG, "A2A_FRAME_TOO_LARGE");
        }
        ciborium::from_reader(bytes).map_err(|e| err!(EINVAL, "CBOR_DECODE", "{e}"))
    }
}

/// Response payload returned over an A2A mTLS channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct A2aResponse {
    /// Whether the call was authorized and executed.
    pub success: bool,
    /// Error code if rejected (e.g. `POP_BAD_SIGNATURE`, `POP_CHANNEL_BINDING_MISMATCH`, `MTLS_DISABLED`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Human-readable error message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    /// Result payload (bytes / JSON).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Vec<u8>>,
}

impl A2aResponse {
    /// Encode as CBOR bytes.
    pub fn to_cbor(&self) -> EnclaveResult<Vec<u8>> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out).map_err(|e| err!(EINVAL, "CBOR_ENCODE", "{e}"))?;
        Ok(out)
    }

    /// Decode from CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> EnclaveResult<Self> {
        if bytes.len() > MAX_A2A_FRAME_BYTES {
            fail!(E2BIG, "A2A_FRAME_TOO_LARGE");
        }
        ciborium::from_reader(bytes).map_err(|e| err!(EINVAL, "CBOR_DECODE", "{e}"))
    }
}

/// Export 32-byte RFC 9266 `EXPORTER-Channel-Binding` from an active TLS connection.
pub fn export_channel_binding<T>(conn: &rustls::ConnectionCommon<T>) -> EnclaveResult<[u8; 32]> {
    let mut out = [0u8; 32];
    conn.export_keying_material(&mut out, b"EXPORTER-Channel-Binding", None)
        .map_err(|e| err!(EIO, "TLS_EXPORTER_FAILED", "{e}"))?;
    Ok(out)
}

/// Extract peer SPIFFE ID from an authenticated TLS connection.
pub fn extract_peer_spiffe<T>(conn: &rustls::ConnectionCommon<T>) -> EnclaveResult<SpiffeId> {
    let certs = conn
        .peer_certificates()
        .ok_or_else(|| err!(EACCES, "PEER_CERTIFICATE_MISSING"))?;
    if certs.is_empty() {
        fail!(EACCES, "PEER_CERTIFICATE_EMPTY");
    }
    extract_spiffe_id(certs[0].as_ref())
}

/// Build `rustls::ClientConfig` for SPIFFE mTLS.
pub fn make_client_config(cfg: &A2aClientConfig) -> EnclaveResult<Arc<rustls::ClientConfig>> {
    let mut verifier = SpiffeCertVerifier::new(&cfg.trust_domain, &cfg.ca_bundle_der)?;
    if let Some(ref peer) = cfg.expected_server_id {
        verifier = verifier.with_exact_peer(peer.clone());
    }

    let cert_chain: Vec<CertificateDer<'static>> = cfg
        .svid
        .cert_der_chain
        .iter()
        .map(|c| CertificateDer::from(c.clone()))
        .collect();
    let private_key = PrivateKeyDer::Pkcs8(cfg.svid.private_key_der.clone().into());

    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| err!(EINVAL, "TLS_VERSION_FAILED", "{e}"))?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(verifier))
    .with_client_auth_cert(cert_chain, private_key)
    .map_err(|e| err!(EINVAL, "CLIENT_AUTH_FAILED", "{e}"))?;

    Ok(Arc::new(builder))
}

/// Build `rustls::ServerConfig` for SPIFFE mTLS.
pub fn make_server_config(cfg: &A2aServerConfig) -> EnclaveResult<Arc<rustls::ServerConfig>> {
    let mut verifier = SpiffeCertVerifier::new(&cfg.trust_domain, &cfg.ca_bundle_der)?;
    if let Some(ref allowed) = cfg.allowed_client_id {
        verifier = verifier.with_exact_peer(allowed.clone());
    }

    let cert_chain: Vec<CertificateDer<'static>> = cfg
        .svid
        .cert_der_chain
        .iter()
        .map(|c| CertificateDer::from(c.clone()))
        .collect();
    let private_key = PrivateKeyDer::Pkcs8(cfg.svid.private_key_der.clone().into());

    let builder = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| err!(EINVAL, "TLS_VERSION_FAILED", "{e}"))?
    .with_client_cert_verifier(Arc::new(verifier))
    .with_single_cert(cert_chain, private_key)
    .map_err(|e| err!(EINVAL, "SERVER_CERT_FAILED", "{e}"))?;

    Ok(Arc::new(builder))
}

/// Write length-prefixed frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> EnclaveResult<()> {
    if bytes.len() > MAX_A2A_FRAME_BYTES {
        fail!(E2BIG, "A2A_FRAME_TOO_LARGE");
    }
    let len = u32::try_from(bytes.len()).map_err(|_| err!(E2BIG, "A2A_FRAME_TOO_LARGE"))?;
    w.write_all(&len.to_be_bytes())
        .await
        .map_err(|e| err!(EIO, "WRITE_LEN_FAILED", "{e}"))?;
    w.write_all(bytes)
        .await
        .map_err(|e| err!(EIO, "WRITE_BODY_FAILED", "{e}"))?;
    w.flush()
        .await
        .map_err(|e| err!(EIO, "FLUSH_FAILED", "{e}"))?;
    Ok(())
}

/// Read length-prefixed frame.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> EnclaveResult<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)
        .await
        .map_err(|e| err!(EIO, "READ_LEN_FAILED", "{e}"))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_A2A_FRAME_BYTES {
        fail!(
            E2BIG,
            "A2A_FRAME_TOO_LARGE",
            "frame length {len} exceeds {MAX_A2A_FRAME_BYTES}"
        );
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)
        .await
        .map_err(|e| err!(EIO, "READ_BODY_FAILED", "{e}"))?;
    Ok(body)
}

/// An A2A mTLS client.
#[derive(Clone)]
pub struct A2aClient {
    tls_connector: tokio_rustls::TlsConnector,
    server_name: ServerName<'static>,
    spiffe_id: SpiffeId,
}

impl std::fmt::Debug for A2aClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("A2aClient")
            .field("spiffe_id", &self.spiffe_id)
            .field("server_name", &self.server_name)
            .finish()
    }
}

impl A2aClient {
    /// Create a new A2A client.
    pub fn new(cfg: A2aClientConfig) -> EnclaveResult<Self> {
        let spiffe_id = cfg.svid.spiffe_id.clone();
        let server_name = ServerName::try_from(cfg.trust_domain.clone())
            .map_err(|e| err!(EINVAL, "INVALID_SERVER_NAME", "{e}"))?;
        let client_config = make_client_config(&cfg)?;
        let tls_connector = tokio_rustls::TlsConnector::from(client_config);
        Ok(Self {
            tls_connector,
            server_name,
            spiffe_id,
        })
    }

    /// Client's own SPIFFE ID.
    pub fn spiffe_id(&self) -> &SpiffeId {
        &self.spiffe_id
    }

    /// Connect to a remote server over the given async stream (e.g. TcpStream).
    pub async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
    ) -> EnclaveResult<A2aClientSession<S>> {
        let tls_stream = self
            .tls_connector
            .connect(self.server_name.clone(), stream)
            .await
            .map_err(|e| err!(EIO, "TLS_CONNECT_FAILED", "{e}"))?;

        let cb = export_channel_binding(tls_stream.get_ref().1)?;
        let server_spiffe = extract_peer_spiffe(tls_stream.get_ref().1)?;

        Ok(A2aClientSession {
            tls_stream,
            channel_binding: cb,
            server_spiffe,
        })
    }
}

/// An active client mTLS session.
pub struct A2aClientSession<S> {
    tls_stream: tokio_rustls::client::TlsStream<S>,
    channel_binding: [u8; 32],
    server_spiffe: SpiffeId,
}

impl<S: AsyncRead + AsyncWrite + Unpin> A2aClientSession<S> {
    /// The 32-byte RFC 9266 channel binding of this session.
    pub fn channel_binding(&self) -> [u8; 32] {
        self.channel_binding
    }

    /// The authenticated server's SPIFFE ID.
    pub fn server_spiffe(&self) -> &SpiffeId {
        &self.server_spiffe
    }

    /// Send a request and wait for the response.
    pub async fn send_request(&mut self, req: &A2aRequest) -> EnclaveResult<A2aResponse> {
        let payload = req.to_cbor()?;
        write_frame(&mut self.tls_stream, &payload).await?;
        let resp_bytes = read_frame(&mut self.tls_stream).await?;
        A2aResponse::from_cbor(&resp_bytes)
    }
}

impl<S> std::fmt::Debug for A2aClientSession<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("A2aClientSession")
            .field("server_spiffe", &self.server_spiffe)
            .field("channel_binding", &hex::encode(&self.channel_binding[..8]))
            .finish()
    }
}

/// An A2A mTLS server.
#[derive(Clone)]
pub struct A2aServer {
    tls_acceptor: tokio_rustls::TlsAcceptor,
    spiffe_id: SpiffeId,
}

impl std::fmt::Debug for A2aServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("A2aServer")
            .field("spiffe_id", &self.spiffe_id)
            .finish()
    }
}

impl A2aServer {
    /// Create a new A2A server.
    pub fn new(cfg: A2aServerConfig) -> EnclaveResult<Self> {
        let spiffe_id = cfg.svid.spiffe_id.clone();
        let server_config = make_server_config(&cfg)?;
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        Ok(Self {
            tls_acceptor,
            spiffe_id,
        })
    }

    /// Server's own SPIFFE ID.
    pub fn spiffe_id(&self) -> &SpiffeId {
        &self.spiffe_id
    }

    /// Accept an incoming connection on an async stream.
    pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
    ) -> EnclaveResult<A2aServerSession<S>> {
        let tls_stream = self
            .tls_acceptor
            .accept(stream)
            .await
            .map_err(|e| err!(EIO, "TLS_ACCEPT_FAILED", "{e}"))?;

        let cb = export_channel_binding(tls_stream.get_ref().1)?;
        let client_spiffe = extract_peer_spiffe(tls_stream.get_ref().1)?;

        Ok(A2aServerSession {
            tls_stream,
            channel_binding: cb,
            client_spiffe,
        })
    }
}

/// An active server mTLS session.
pub struct A2aServerSession<S> {
    tls_stream: tokio_rustls::server::TlsStream<S>,
    channel_binding: [u8; 32],
    client_spiffe: SpiffeId,
}

impl<S: AsyncRead + AsyncWrite + Unpin> A2aServerSession<S> {
    /// The 32-byte RFC 9266 channel binding of this session.
    pub fn channel_binding(&self) -> [u8; 32] {
        self.channel_binding
    }

    /// The authenticated client's SPIFFE ID.
    pub fn client_spiffe(&self) -> &SpiffeId {
        &self.client_spiffe
    }

    /// Read incoming request.
    pub async fn read_request(&mut self) -> EnclaveResult<A2aRequest> {
        let req_bytes = read_frame(&mut self.tls_stream).await?;
        A2aRequest::from_cbor(&req_bytes)
    }

    /// Send response back to the client.
    pub async fn send_response(&mut self, resp: &A2aResponse) -> EnclaveResult<()> {
        let payload = resp.to_cbor()?;
        write_frame(&mut self.tls_stream, &payload).await
    }

    /// Authorize and process an incoming request using the provided PDP and CapabilityHeap.
    pub async fn process_one_call(
        &mut self,
        pdp: &mut Pdp,
        heap: &CapabilityHeap,
        now_mach_ns: u64,
        now_utc_ms: u64,
    ) -> EnclaveResult<A2aResponse> {
        let req = self.read_request().await?;

        // Fail-closed transport assertion: must be MtlsExporter
        if req.wire.transport != Transport::MtlsExporter {
            let resp = A2aResponse {
                success: false,
                error_code: Some("POP_TRANSPORT_MISMATCH".to_owned()),
                error_message: Some(
                    "A2A remote calls must carry MtlsExporter transport".to_owned(),
                ),
                payload: None,
            };
            self.send_response(&resp).await?;
            return Ok(resp);
        }

        let peer = PeerCredentials::mtls(self.channel_binding);
        let tool_req = ToolCallRequest {
            agent: self.client_spiffe.to_string(),
            tool: ToolResource {
                name: req.tool_name,
                action_class: enclave_core::ActionClass::A1,
                sink_clearance: enclave_core::Conf::C2,
                namespace: req.target_namespace,
                mutates_root: false,
            },
            arg_slots: vec![],
            // No trusted per-argument schema is supplied on this path.
            literal_structural: true,
            args_jcs: req.args_json.into_bytes(),
            row_count: 10,
            qif_mb: req.qif_mb,
            hw_grant: false,
            wire_cbor: req.wire.to_cbor()?,
        };

        let decision = pdp.authorize(heap, &peer, &tool_req, now_mach_ns, now_utc_ms);
        let resp = match decision {
            Ok(d) if d.allow => A2aResponse {
                success: true,
                error_code: None,
                error_message: None,
                payload: Some(b"{\"status\":\"delegation_executed\"}".to_vec()),
            },
            Ok(d) => {
                let code = d
                    .biscuit_error
                    .as_deref()
                    .map(|s| {
                        if let Some((_, rest)) = s.split_once(": ") {
                            if let Some((code, _)) = rest.split_once(' ') {
                                code.to_owned()
                            } else {
                                rest.to_owned()
                            }
                        } else {
                            s.to_owned()
                        }
                    })
                    .or_else(|| d.cedar_reasons.first().cloned());
                A2aResponse {
                    success: false,
                    error_code: code,
                    error_message: Some(format!(
                        "denied by PDP: cedar={:?}, biscuit={:?}",
                        d.cedar_reasons, d.biscuit_error
                    )),
                    payload: None,
                }
            }
            Err(e) => A2aResponse {
                success: false,
                error_code: Some(e.reason),
                error_message: Some(e.detail),
                payload: None,
            },
        };

        self.send_response(&resp).await?;
        Ok(resp)
    }
}

impl<S> std::fmt::Debug for A2aServerSession<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("A2aServerSession")
            .field("client_spiffe", &self.client_spiffe)
            .field("channel_binding", &hex::encode(&self.channel_binding[..8]))
            .finish()
    }
}
