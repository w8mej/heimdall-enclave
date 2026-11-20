//! SPIFFE X.509 certificate verification for mutual TLS (mTLS).

use std::sync::Arc;

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::ParsedCertificate;
use rustls::{DigitallySignedStruct, DistinguishedName, RootCertStore};
use x509_parser::prelude::*;

use crate::a2a::spiffe::SpiffeId;

/// Extract the sole SPIFFE URI SAN, refusing ambiguity and trailing DER bytes.
pub fn extract_spiffe_id(cert_der: &[u8]) -> EnclaveResult<SpiffeId> {
    let (remainder, x509) =
        parse_x509_certificate(cert_der).map_err(|e| err!(EINVAL, "X509_PARSE_FAILED", "{e}"))?;
    if !remainder.is_empty() {
        fail!(EINVAL, "X509_TRAILING_BYTES");
    }
    let mut identity = None;
    let mut san_extensions = 0;
    for ext in x509.iter_extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            san_extensions += 1;
            if san_extensions > 1 {
                fail!(EINVAL, "SPIFFE_MULTIPLE_SAN_EXTENSIONS");
            }
            for name in &san.general_names {
                if let GeneralName::URI(uri) = name {
                    if identity.is_some() {
                        fail!(EINVAL, "SPIFFE_MULTIPLE_URI_SANS");
                    }
                    identity = Some(*uri);
                }
            }
        }
    }
    if let Some(uri) = identity {
        return SpiffeId::parse(uri);
    }
    fail!(
        EINVAL,
        "SPIFFE_ID_MISSING",
        "no URI SAN found in certificate"
    );
}

/// SPIFFE certificate verifier for both server-side and client-side mTLS.
#[derive(Debug, Clone)]
pub struct SpiffeCertVerifier {
    expected_trust_domain: String,
    roots: Arc<RootCertStore>,
    allowed_peer_id: Option<SpiffeId>,
}

impl SpiffeCertVerifier {
    /// Create a new verifier for the given trust domain and trusted roots.
    pub fn new(expected_trust_domain: &str, trusted_roots_der: &[Vec<u8>]) -> EnclaveResult<Self> {
        let mut roots = RootCertStore::empty();
        for r in trusted_roots_der {
            roots
                .add(CertificateDer::from(r.clone()))
                .map_err(|e| err!(EINVAL, "INVALID_ROOT_CERT", "{e}"))?;
        }
        Ok(Self {
            expected_trust_domain: expected_trust_domain.to_owned(),
            roots: Arc::new(roots),
            allowed_peer_id: None,
        })
    }

    /// Constrain verification to a specific exact SPIFFE ID.
    pub fn with_exact_peer(mut self, peer_id: SpiffeId) -> Self {
        self.allowed_peer_id = Some(peer_id);
        self
    }

    /// Verify an end-entity certificate against the trusted roots and SPIFFE ID constraints.
    pub fn verify_spiffe_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<SpiffeId, rustls::Error> {
        // 1. Verify chain signatures against roots
        let parsed = ParsedCertificate::try_from(end_entity)?;
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &parsed,
            &self.roots,
            intermediates,
            now,
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .all,
        )?;

        // Lifetime is the revocation bound: no CRL/OCSP is configured for SVIDs.
        let (_, cert) = parse_x509_certificate(end_entity.as_ref())
            .map_err(|_| rustls::Error::General("SVID_PARSE_FAILED".into()))?;
        let validity = cert.validity();
        let ttl = validity
            .not_after
            .timestamp()
            .checked_sub(validity.not_before.timestamp());
        if !matches!(ttl, Some(1..=3600)) {
            return Err(rustls::Error::General(
                "SVID_LIFETIME_EXCEEDS_ONE_HOUR".into(),
            ));
        }

        // 2. Extract and validate SPIFFE ID
        let spiffe_id = extract_spiffe_id(end_entity.as_ref())
            .map_err(|e| rustls::Error::General(format!("SPIFFE extract failed: {e}")))?;

        if spiffe_id.trust_domain() != self.expected_trust_domain {
            return Err(rustls::Error::General(format!(
                "TRUST_DOMAIN_MISMATCH: expected {}, got {}",
                self.expected_trust_domain,
                spiffe_id.trust_domain()
            )));
        }

        if let Some(ref allowed) = self.allowed_peer_id {
            if &spiffe_id != allowed {
                return Err(rustls::Error::General(format!(
                    "PEER_SPIFFE_ID_REJECTED: expected {}, got {}",
                    allowed, spiffe_id
                )));
            }
        }

        Ok(spiffe_id)
    }
}

impl ServerCertVerifier for SpiffeCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.verify_spiffe_cert(end_entity, intermediates, now)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl ClientCertVerifier for SpiffeCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.verify_spiffe_cert(end_entity, intermediates, now)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
