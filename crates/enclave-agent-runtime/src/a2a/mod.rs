//! Cross-node A2A over mTLS with SPIFFE X.509-SVIDs (FS-704 §3.4, GAP-35, D-35a).
//!
//! Provides mutual TLS authentication anchored in SPIFFE trust domains with
//! RFC 9266 `tls-exporter` channel binding bound directly into the PoP-Biscuit token.

/// Marker string present only when L2 A2A is compiled in.
pub const A2A_MARKER: &str = "MCPMac A2A mTLS transport (L2 only)";

pub mod spiffe;
pub mod transport;
pub mod verifier;

pub use spiffe::{SpiffeId, SpiffeSvid, SpiffeWorkloadSource};
pub use transport::{
    export_channel_binding, extract_peer_spiffe, make_client_config, make_server_config,
    read_frame, write_frame, A2aClient, A2aClientConfig, A2aClientSession, A2aRequest, A2aResponse,
    A2aServer, A2aServerConfig, A2aServerSession, MAX_A2A_FRAME_BYTES,
};
pub use verifier::SpiffeCertVerifier;
