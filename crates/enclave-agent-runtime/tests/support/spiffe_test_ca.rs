//! Test-only CA; not linked into the runtime library or binaries.
use enclave_agent_runtime::a2a::{SpiffeId, SpiffeSvid, SpiffeWorkloadSource};
use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};

/// In-repo test CA for minting SPIFFE X.509-SVIDs (RFC 5280 / SPIFFE standard).
pub struct SpiffeTestCa {
    trust_domain: String,
    ca_cert_der: Vec<u8>,
    ca_cert: rcgen::Certificate,
}

impl std::fmt::Debug for SpiffeTestCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeTestCa")
            .field("trust_domain", &self.trust_domain)
            .field("ca_cert_len", &self.ca_cert_der.len())
            .finish()
    }
}

impl SpiffeTestCa {
    /// Create a new test CA for the given trust domain.
    pub fn new(trust_domain: &str) -> EnclaveResult<Self> {
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(
            rcgen::DnType::CommonName,
            format!("{trust_domain} SPIFFE Test Root CA"),
        );
        params.distinguished_name = dn;
        let ca_cert = rcgen::Certificate::from_params(params)
            .map_err(|e| err!(EINVAL, "CA_GEN_FAILED", "{e}"))?;
        let ca_cert_der = ca_cert
            .serialize_der()
            .map_err(|e| err!(EINVAL, "CA_DER_FAILED", "{e}"))?;
        Ok(Self {
            trust_domain: trust_domain.to_owned(),
            ca_cert_der,
            ca_cert,
        })
    }

    /// Returns the CA trust bundle DER.
    pub fn ca_bundle_der(&self) -> Vec<Vec<u8>> {
        vec![self.ca_cert_der.clone()]
    }

    /// Issue an X.509 SVID for the given SPIFFE ID.
    pub fn issue_svid(&self, spiffe_id: &SpiffeId) -> EnclaveResult<SpiffeSvid> {
        self.issue_svid_with_validity(spiffe_id, -60, 300)
    }

    /// Explicit offsets let tests exercise the actual chain verifier's time policy.
    pub fn issue_svid_with_validity(
        &self,
        spiffe_id: &SpiffeId,
        not_before_seconds: i64,
        not_after_seconds: i64,
    ) -> EnclaveResult<SpiffeSvid> {
        if spiffe_id.trust_domain() != self.trust_domain {
            fail!(
                EINVAL,
                "TRUST_DOMAIN_MISMATCH",
                "CA domain {} != SVID domain {}",
                self.trust_domain,
                spiffe_id.trust_domain()
            );
        }
        let mut params = rcgen::CertificateParams::default();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, spiffe_id.as_str());
        params.distinguished_name = dn;
        params.subject_alt_names = vec![rcgen::SanType::URI(spiffe_id.as_str().to_string())];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now + time::Duration::seconds(not_before_seconds);
        params.not_after = now + time::Duration::seconds(not_after_seconds);

        let client_cert = rcgen::Certificate::from_params(params)
            .map_err(|e| err!(EINVAL, "CERT_GEN_FAILED", "{e}"))?;
        let cert_der = client_cert
            .serialize_der_with_signer(&self.ca_cert)
            .map_err(|e| err!(EINVAL, "CERT_SIGN_FAILED", "{e}"))?;
        let private_key_der = client_cert.serialize_private_key_der();

        Ok(SpiffeSvid {
            spiffe_id: spiffe_id.clone(),
            cert_der_chain: vec![cert_der, self.ca_cert_der.clone()],
            private_key_der,
        })
    }
}

impl SpiffeWorkloadSource for SpiffeTestCa {
    fn fetch_svid(&self) -> EnclaveResult<SpiffeSvid> {
        let id = SpiffeId::new(&self.trust_domain, "/enclave/uid/704/default")?;
        self.issue_svid(&id)
    }

    fn fetch_bundle(&self) -> EnclaveResult<Vec<Vec<u8>>> {
        Ok(self.ca_bundle_der())
    }
}
