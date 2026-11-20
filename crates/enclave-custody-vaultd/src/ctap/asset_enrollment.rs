//! Independently signed asset admission. AAGUID/USB enumeration and a new local
//! credential are not independent inventory. Activation requires an issuer
//! receipt over exact attested pending evidence, host and SEP identity.
use super::assertion::EnrolledCredential;
use enclave_core::{err, error::EnclaveResult, fail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Approved L3 attestation choice; organization policy cannot be weakened by RPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationMode {
    /// Basic manufacturer chain plus independent signed physical-asset binding.
    BasicWithIndependentAsset,
    /// A separately provisioned enterprise attestation identity is mandatory.
    EnterpriseRequired,
}
/// Administrator preflight policy, signed before makeCredential is authorized.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetEnrollmentPolicy {
    /// Schema version1.
    pub version: u32,
    /// Monotonic policy generation; service persists floor before activation.
    pub revision: u64,
    /// Exact separately configured host identity.
    pub host_id: String,
    /// Exact independently inventoried asset identity.
    pub asset_id: String,
    /// Independently authorized custodian identity.
    pub custodian_id: String,
    /// Permitted model; not itself asset proof.
    pub aaguid: [u8; 16],
    /// Administrator-selected attestation mode.
    pub mode: AttestationMode,
    /// Required independently provisioned enterprise leaf SHA256; never inferred
    /// from firmware or an Enterprise boolean. None for the Basic alternative.
    pub enterprise_leaf_sha256: Option<[u8; 32]>,
    /// Organization-specific rationale displayed at first setup.
    pub rationale: String,
    /// Inclusive issue time and exclusive expiry.
    pub issued_unix: i64,
    /// Exclusive expiry; refreshed policy never revives earlier consumed state.
    pub expires_unix: i64,
}
/// Independent issuer signature; issuer keys come from administrator/TUF pins.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAssetEnrollmentPolicy {
    /// Exact signed policy.
    pub policy: AssetEnrollmentPolicy,
    /// Raw64-byte Ed25519 signature.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}
/// Opaque independently verified preflight capability.
#[derive(Debug, Clone)]
pub struct VerifiedAssetEnrollmentPolicy {
    policy: AssetEnrollmentPolicy,
    digest: [u8; 32],
}
fn message(domain: &[u8], value: &impl Serialize) -> EnclaveResult<Vec<u8>> {
    let mut m = domain.to_vec();
    m.extend(enclave_core::jcs::to_jcs_bytes(value)?);
    Ok(m)
}
fn signature(key: &ed25519_dalek::VerifyingKey, msg: &[u8], sig: &[u8]) -> EnclaveResult<()> {
    let sig = ed25519_dalek::Signature::from_slice(sig)
        .map_err(|_| err!(EACCES, "ASSET_ISSUER_SIGNATURE"))?;
    key.verify_strict(msg, &sig)
        .map_err(|_| err!(EACCES, "ASSET_ISSUER_SIGNATURE"))
}
impl AssetEnrollmentPolicy {
    /// Exact issuer preimage.
    pub fn signing_message(&self) -> EnclaveResult<Vec<u8>> {
        message(b"MCPMac-AssetEnrollmentPolicy-v1\0", self)
    }
}
impl SignedAssetEnrollmentPolicy {
    /// Expected host/asset/custodian are independently configured, never chosen
    /// by the enrollment caller. The signed generation must meet durable floors.
    pub fn verify(
        &self,
        key: &ed25519_dalek::VerifyingKey,
        host: &str,
        asset: &str,
        custodian: &str,
        minimum_revision: u64,
        now: i64,
    ) -> EnclaveResult<VerifiedAssetEnrollmentPolicy> {
        let p = &self.policy;
        let valid = |v: &str| !v.is_empty() && v.len() <= 256 && !v.chars().any(char::is_control);
        if p.version != 1
            || p.revision == 0
            || p.revision < minimum_revision
            || p.host_id != host
            || p.asset_id != asset
            || p.custodian_id != custodian
            || ![host, asset, custodian, &p.rationale]
                .into_iter()
                .all(valid)
            || p.issued_unix < 0
            || now < p.issued_unix
            || now >= p.expires_unix
            || (p.mode == AttestationMode::EnterpriseRequired) != p.enterprise_leaf_sha256.is_some()
        {
            fail!(EACCES, "ASSET_ENROLLMENT_POLICY");
        }
        let bytes = p.signing_message()?;
        signature(key, &bytes, &self.signature)?;
        Ok(VerifiedAssetEnrollmentPolicy {
            policy: p.clone(),
            digest: Sha256::digest(bytes).into(),
        })
    }
}
impl VerifiedAssetEnrollmentPolicy {
    /// Exact signed policy digest, signed by the fresh setup SEP approval.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Organization-selected mode, never a caller downgrade.
    pub fn mode(&self) -> AttestationMode {
        self.policy.mode
    }
    /// Strict pre-write and pre-activation revalidation.
    pub fn check(&self, aaguid: &[u8; 16], now: i64) -> EnclaveResult<()> {
        if *aaguid != self.policy.aaguid
            || now < self.policy.issued_unix
            || now >= self.policy.expires_unix
        {
            fail!(EACCES, "ASSET_ENROLLMENT_SCOPE_OR_TIME");
        }
        Ok(())
    }
    /// Required first-setup disclosure; helper must display this exact reason
    /// and sign this policy digest after fresh actual Touch ID and dwell.
    pub fn localized_reason(&self) -> String {
        let mode=match self.policy.mode {
            AttestationMode::BasicWithIndependentAsset=>"Basic attestation identifies a manufacturer/model, not a unique physical asset. Independent signed asset enrollment is required; Enterprise attestation is not provided by this mode.",
            AttestationMode::EnterpriseRequired=>"Your organization requires Enterprise attestation and a separately provisioned enterprise device identity; Basic attestation cannot substitute.",
        };
        format!("[First L3 setup] {mode} SEP and CTAP authentication/key agreement remain classical; hybrid vault envelopes do not make the complete hardware path post-quantum. Organization rationale: {}. Asset: {}. Custodian: {}.",self.policy.rationale,self.policy.asset_id,self.policy.custodian_id)
    }
    pub(crate) fn leaf(&self) -> Option<[u8; 32]> {
        self.policy.enterprise_leaf_sha256
    }
}
/// Fresh SEP-verified disclosure, consumed by the pending credential operation.
#[derive(Debug)]
pub struct VerifiedSetupDisclosure {
    policy: [u8; 32],
    sep_public_key: Vec<u8>,
    evidence: SetupDisclosureEvidence,
    deadline_ns: u64,
}
/// Public disclosure proof. Excludes the protected SEP key blob and all
/// enrollment-private output; retained for exact independent issuer review.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupDisclosureEvidence {
    localized_reason: String,
    policy_sha256: [u8; 32],
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
    start_ns_hex: String,
    visible_ns_hex: String,
    approved_ns_hex: String,
    #[serde(with = "serde_bytes")]
    sep_signature: Vec<u8>,
}
impl SetupDisclosureEvidence {
    fn ns(value: &str) -> EnclaveResult<u64> {
        if value.len() != 16
            || !value
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
        {
            fail!(EACCES, "ASSET_SETUP_TIME_ENCODING");
        }
        u64::from_str_radix(value, 16).map_err(|_| err!(EACCES, "ASSET_SETUP_TIME_ENCODING"))
    }
    fn verify(&self, policy: &VerifiedAssetEnrollmentPolicy, sep: &[u8]) -> EnclaveResult<()> {
        if self.policy_sha256 != policy.digest || self.localized_reason != policy.localized_reason()
        {
            fail!(EACCES, "ASSET_SETUP_DISCLOSURE_BINDING");
        }
        let start = Self::ns(&self.start_ns_hex)?;
        let visible = Self::ns(&self.visible_ns_hex)?;
        let approved = Self::ns(&self.approved_ns_hex)?;
        let prompt = crate::biometric::BiometricPrompt {
            localized_reason: self.localized_reason.clone(),
            d_jcs: self.policy_sha256.to_vec(),
            nonce: self.nonce.clone(),
            t_start_ns: start,
            bio_key_blob: vec![],
        };
        let outcome = crate::biometric::BiometricOutcome::Approved {
            sep_signature: self.sep_signature.clone(),
            visible_at_ns: visible,
            approved_at_ns: approved,
            enrolled_pubkey: None,
            enrolled_blob: None,
        };
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(sep)
            .map_err(|_| err!(EACCES, "ASSET_SETUP_SEP_KEY"))?;
        crate::biometric::verify_approval(&key, &prompt, &outcome)?;
        let deadline = start
            .checked_add(crate::ceremony::CEREMONY_BUDGET_NS)
            .ok_or_else(|| err!(ETIMEDOUT, "ASSET_SETUP_DEADLINE"))?;
        if approved >= deadline {
            fail!(EACCES, "ASSET_SETUP_DISCLOSURE_BINDING");
        }
        Ok(())
    }
    /// Unique server-generated nonce. Durable service consumes it before any
    /// makeCredential attempt, including failed or timed-out attempts.
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }
}

impl VerifiedSetupDisclosure {
    /// The expected prompt is generated by UID703; only the genuine SEP outcome
    /// verifies it. A caller boolean or the helper's public-key claim is insufficient.
    pub fn verify(
        policy: &VerifiedAssetEnrollmentPolicy,
        sep: &p256::ecdsa::VerifyingKey,
        prompt: &crate::biometric::BiometricPrompt,
        outcome: &crate::biometric::BiometricOutcome,
    ) -> EnclaveResult<Self> {
        if prompt.d_jcs.as_slice() != policy.digest
            || prompt.localized_reason != policy.localized_reason()
        {
            fail!(EACCES, "ASSET_SETUP_DISCLOSURE_BINDING");
        }
        crate::biometric::verify_approval(sep, prompt, outcome)?;
        let deadline_ns = prompt
            .t_start_ns
            .checked_add(crate::ceremony::CEREMONY_BUDGET_NS)
            .ok_or_else(|| err!(ETIMEDOUT, "ASSET_SETUP_DEADLINE"))?;
        let now = enclave_core::power::continuous_time_ns();
        if prompt.t_start_ns > now || now >= deadline_ns {
            fail!(ETIMEDOUT, "ASSET_SETUP_DEADLINE");
        }
        let crate::biometric::BiometricOutcome::Approved {sep_signature,visible_at_ns,approved_at_ns,..}=outcome
            else {fail!(EACCES,"ASSET_SETUP_DISCLOSURE_BINDING");};
        // Continuous nanoseconds require the full u64 range. Fixed lower-case
        // hex preserves exact timestamps without exceeding JCS safe integers.
        let evidence = SetupDisclosureEvidence {
            localized_reason: prompt.localized_reason.clone(),
            policy_sha256: policy.digest,
            nonce: prompt.nonce.clone(),
            start_ns_hex: format!("{:016x}", prompt.t_start_ns),
            visible_ns_hex: format!("{visible_at_ns:016x}"),
            approved_ns_hex: format!("{approved_at_ns:016x}"),
            sep_signature: sep_signature.clone(),
        };
        let sep_public_key = sep.to_encoded_point(false).as_bytes().to_vec();
        evidence.verify(policy, &sep_public_key)?;
        Ok(Self {
            policy: policy.digest,
            sep_public_key,
            evidence,
            deadline_ns,
        })
    }
    pub(crate) fn consume(
        self,
        policy: &VerifiedAssetEnrollmentPolicy,
    ) -> EnclaveResult<(Vec<u8>, SetupDisclosureEvidence, u64)> {
        if self.policy != policy.digest
            || enclave_core::power::continuous_time_ns() >= self.deadline_ns
        {
            fail!(EACCES, "ASSET_SETUP_DISCLOSURE_BINDING");
        }
        Ok((self.sep_public_key, self.evidence, self.deadline_ns))
    }
}
/// Public attested pending evidence. Export to the independent inventory issuer
/// only through the configured enrollment workflow. No private/key material.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingAssetEnrollment {
    pub(crate) credential: EnrolledCredential,
    pub(crate) policy_digest: [u8; 32],
    pub(crate) sep_public_key: Vec<u8>,
    /// Exact public SEP disclosure proof, covered by the pending digest.
    pub disclosure_evidence: SetupDisclosureEvidence,
    pub(crate) evidence_sha256: [u8; 32],
    /// Exact public makeCredential response and challenge, for independent
    /// attestation/inventory review. This is not an assertion or private key.
    #[serde(with = "serde_bytes")]
    pub attestation_evidence: Vec<u8>,
    pub(crate) mode: AttestationMode,
}
impl PendingAssetEnrollment {
    /// Exact independent-issuer receipt binding over attested credential, host
    /// policy, mode and actual SEP public key. Pending evidence is not activation.
    pub fn digest(&self) -> EnclaveResult<[u8; 32]> {
        if self.attestation_evidence.len() > 64 * 1024
            || <[u8; 32]>::from(Sha256::digest(&self.attestation_evidence)) != self.evidence_sha256
        {
            fail!(EACCES, "ASSET_ATTESTATION_EVIDENCE");
        }
        Ok(Sha256::digest(message(b"MCPMac-PendingAssetEnrollment-v1\0", self)?).into())
    }
    /// Public credential reference for issuer review; unusable as an admission capability.
    pub fn credential(&self) -> &EnrolledCredential {
        &self.credential
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn policy(issuer: &SigningKey, mode: AttestationMode) -> SignedAssetEnrollmentPolicy {
        let policy = AssetEnrollmentPolicy {
            version: 1,
            revision: 3,
            host_id: "fixture-host".into(),
            asset_id: "fixture-asset".into(),
            custodian_id: "fixture-custodian".into(),
            aaguid: [3; 16],
            mode,
            enterprise_leaf_sha256: (mode == AttestationMode::EnterpriseRequired)
                .then_some([5; 32]),
            rationale: "independently managed fixture inventory".into(),
            issued_unix: 1,
            expires_unix: 100,
        };
        let signature = issuer
            .sign(&policy.signing_message().unwrap())
            .to_bytes()
            .to_vec();
        SignedAssetEnrollmentPolicy { policy, signature }
    }
    fn verify(
        p: &SignedAssetEnrollmentPolicy,
        issuer: &SigningKey,
    ) -> VerifiedAssetEnrollmentPolicy {
        p.verify(
            &issuer.verifying_key(),
            "fixture-host",
            "fixture-asset",
            "fixture-custodian",
            3,
            2,
        )
        .unwrap()
    }
    fn pending(policy: &VerifiedAssetEnrollmentPolicy) -> PendingAssetEnrollment {
        let credential = EnrolledCredential {
            credential_id: vec![1, 2, 3],
            key: super::super::assertion::CredentialKey::Ed25519(
                SigningKey::from_bytes(&[8; 32]).verifying_key(),
            ),
            aaguid: [3; 16],
            firmware_version: 0x050800,
        };
        let attestation_evidence = b"synthetic-public-evidence".to_vec();
        use crate::biometric::{BiometricPrompt, BiometricProvider, Scripted, ScriptedCoreAuthUi};
        let mut ui = ScriptedCoreAuthUi::new([Scripted::Approve]);
        let sep = ui.enrolled_key();
        let prompt = BiometricPrompt {
            localized_reason: policy.localized_reason(),
            d_jcs: policy.digest().to_vec(),
            nonce: vec![17; 32],
            t_start_ns: enclave_core::power::continuous_time_ns(),
            bio_key_blob: vec![],
        };
        let outcome = ui.evaluate(&prompt);
        let (sep_public_key, disclosure_evidence, _) =
            VerifiedSetupDisclosure::verify(policy, &sep, &prompt, &outcome)
                .unwrap()
                .consume(policy)
                .unwrap();
        PendingAssetEnrollment {
            credential,
            policy_digest: policy.digest,
            sep_public_key,
            disclosure_evidence,
            evidence_sha256: Sha256::digest(&attestation_evidence).into(),
            attestation_evidence,
            mode: policy.mode(),
        }
    }
    fn receipt(pending: &PendingAssetEnrollment, inventory: &SigningKey) -> AssetEnrollmentReceipt {
        let mut receipt = AssetEnrollmentReceipt {
            version: 1,
            pending_sha256: pending.digest().unwrap(),
            generation: 7,
            issued_unix: 2,
            expires_unix: 90,
            signature: vec![],
        };
        receipt.signature = inventory
            .sign(&receipt.signing_message().unwrap())
            .to_bytes()
            .to_vec();
        receipt
    }
    #[test]
    fn policy_scope_enterprise_requirement_and_independent_receipt_are_exact() {
        let issuer = SigningKey::from_bytes(&[9; 32]);
        let inventory = SigningKey::from_bytes(&[10; 32]);
        let signed = policy(&issuer, AttestationMode::BasicWithIndependentAsset);
        assert!(signed
            .verify(
                &issuer.verifying_key(),
                "other-host",
                "fixture-asset",
                "fixture-custodian",
                3,
                2
            )
            .is_err());
        assert!(signed
            .verify(
                &issuer.verifying_key(),
                "fixture-host",
                "fixture-asset",
                "fixture-custodian",
                4,
                2
            )
            .is_err());
        assert!(signed
            .verify(
                &issuer.verifying_key(),
                "fixture-host",
                "fixture-asset",
                "fixture-custodian",
                3,
                100
            )
            .is_err());
        let verified = verify(&signed, &issuer);
        let pending = pending(&verified);
        let receipt = receipt(&pending, &inventory);
        assert!(receipt
            .clone()
            .activate(pending.clone(), &verified, &issuer.verifying_key(), 7, 3)
            .is_err());
        assert!(receipt
            .clone()
            .activate(pending.clone(), &verified, &inventory.verifying_key(), 8, 3)
            .is_err());
        assert!(receipt
            .clone()
            .activate(
                pending.clone(),
                &verified,
                &inventory.verifying_key(),
                7,
                90
            )
            .is_err());
        let mut swapped = pending.clone();
        swapped.credential.credential_id.push(4);
        assert!(receipt
            .clone()
            .activate(swapped, &verified, &inventory.verifying_key(), 7, 3)
            .is_err());
        let mut swapped = pending.clone();
        swapped.attestation_evidence.push(4);
        assert!(receipt
            .clone()
            .activate(swapped, &verified, &inventory.verifying_key(), 7, 3)
            .is_err());
        receipt
            .activate(pending, &verified, &inventory.verifying_key(), 7, 3)
            .unwrap();
        let enterprise = verify(
            &policy(&issuer, AttestationMode::EnterpriseRequired),
            &issuer,
        );
        assert_ne!(enterprise.digest(), verified.digest());
        assert!(enterprise.localized_reason().contains("Enterprise"));
        assert!(verified
            .localized_reason()
            .contains("not a unique physical asset"));
    }

    #[test]
    fn pending_basic_enrollment_requires_disclosure_then_exact_independent_inventory_receipt() {
        use crate::{
            biometric::{BiometricPrompt, BiometricProvider, Scripted, ScriptedCoreAuthUi},
            ctap::{
                client::{begin_asset_enrollment, CtapClient},
                mds::{MdsAllowlist, MdsEntry, MdsState},
                virtual_device::VirtualAuthenticator,
            },
        };
        let issuer = SigningKey::from_bytes(&[9; 32]);
        let inventory = SigningKey::from_bytes(&[10; 32]);
        let mut device = VirtualAuthenticator::new([3; 16]);
        let mds = MdsState {
            refreshed_at: 1,
            expires_at: 100,
            allowlist: MdsAllowlist {
                entries: vec![MdsEntry {
                    aaguid: hex::encode(device.aaguid),
                    description: "synthetic".into(),
                    min_firmware_version: 0x050700,
                    status_reports: vec![],
                    attestation_public_keys: vec![device.attestation_key_mds()],
                    attestation_root_certificates: vec![],
                }],
            },
        };
        let mut ui = ScriptedCoreAuthUi::new([Scripted::Approve, Scripted::Approve]);
        let sep = ui.enrolled_key();
        let verified = verify(
            &policy(&issuer, AttestationMode::BasicWithIndependentAsset),
            &issuer,
        );
        let prompt = BiometricPrompt {
            localized_reason: verified.localized_reason(),
            d_jcs: verified.digest().to_vec(),
            nonce: vec![6; 32],
            t_start_ns: enclave_core::power::continuous_time_ns(),
            bio_key_blob: vec![],
        };
        let outcome = ui.evaluate(&prompt);
        let disclosure =
            VerifiedSetupDisclosure::verify(&verified, &sep, &prompt, &outcome).unwrap();
        let pending = begin_asset_enrollment(
            &mut CtapClient::open(&mut device).unwrap(),
            &mds,
            &verified,
            disclosure,
            2,
        )
        .unwrap();
        assert!(!pending.attestation_evidence.is_empty());
        let receipt = receipt(&pending, &inventory);
        let enrolled = receipt
            .activate(pending, &verified, &inventory.verifying_key(), 7, 3)
            .unwrap();
        assert!(!enrolled.credential_id.is_empty());

        // An Enterprise-required organization cannot be downgraded to this
        // fixture's Basic raw attestation, before a new credential is created.
        let enterprise = verify(
            &policy(&issuer, AttestationMode::EnterpriseRequired),
            &issuer,
        );
        let prompt = BiometricPrompt {
            localized_reason: enterprise.localized_reason(),
            d_jcs: enterprise.digest().to_vec(),
            nonce: vec![7; 32],
            t_start_ns: enclave_core::power::continuous_time_ns(),
            bio_key_blob: vec![],
        };
        let outcome = ui.evaluate(&prompt);
        let disclosure =
            VerifiedSetupDisclosure::verify(&enterprise, &sep, &prompt, &outcome).unwrap();
        let before = device.export_state();
        assert!(begin_asset_enrollment(
            &mut CtapClient::open(&mut device).unwrap(),
            &mds,
            &enterprise,
            disclosure,
            2
        )
        .unwrap_err()
        .is("ENTERPRISE_ATTESTATION_NOT_ENABLED"));
        assert!(
            device.export_state() == before,
            "refusal must precede makeCredential"
        );
    }
    #[test]
    fn pin_only_l3_pending_requires_one_makecredential_scoped_token_and_signed_uv() {
        use crate::{
            biometric::{BiometricPrompt, BiometricProvider, Scripted, ScriptedCoreAuthUi},
            clock::TestClock,
            ctap::{
                client::{begin_asset_enrollment_capturing_with_pin, CtapClient},
                mds::{MdsAllowlist, MdsEntry, MdsState},
                virtual_device::VirtualAuthenticator,
            },
        };
        let issuer = SigningKey::from_bytes(&[9; 32]);
        let mut device = VirtualAuthenticator::new([3; 16]);
        device.configure_synthetic_pin(b"synthetic-pin");
        let mds = MdsState {
            refreshed_at: 1,
            expires_at: 100,
            allowlist: MdsAllowlist {
                entries: vec![MdsEntry {
                    aaguid: hex::encode(device.aaguid),
                    description: "synthetic".into(),
                    min_firmware_version: 0x050700,
                    status_reports: vec![],
                    attestation_public_keys: vec![device.attestation_key_mds()],
                    attestation_root_certificates: vec![],
                }],
            },
        };
        let active = verify(
            &policy(&issuer, AttestationMode::BasicWithIndependentAsset),
            &issuer,
        );
        let mut ui = ScriptedCoreAuthUi::new([Scripted::Approve]);
        let sep = ui.enrolled_key();
        let prompt = BiometricPrompt {
            localized_reason: active.localized_reason(),
            d_jcs: active.digest().to_vec(),
            nonce: vec![21; 32],
            t_start_ns: enclave_core::power::continuous_time_ns(),
            bio_key_blob: vec![],
        };
        let outcome = ui.evaluate(&prompt);
        let disclosure = VerifiedSetupDisclosure::verify(&active, &sep, &prompt, &outcome).unwrap();
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        device.hub_depth = 2;
        let before = device.export_state();
        assert!(begin_asset_enrollment_capturing_with_pin(
            &mut CtapClient::open(&mut device).unwrap(),
            &mds,
            &active,
            disclosure,
            enclave_core::profile::Profile::L3,
            &TestClock::at(2),
            &cancelled,
            None,
            |_| panic!("hub must never create pending")
        )
        .unwrap_err()
        .is("USB_HUB_FORBIDDEN_L3"));
        assert_eq!(device.export_state(), before);
        device.hub_depth = 1;
        let mut ui = ScriptedCoreAuthUi::new([Scripted::Approve]);
        let sep = ui.enrolled_key();
        let prompt = BiometricPrompt {
            t_start_ns: enclave_core::power::continuous_time_ns(),
            nonce: vec![22; 32],
            ..prompt
        };
        let outcome = ui.evaluate(&prompt);
        let disclosure = VerifiedSetupDisclosure::verify(&active, &sep, &prompt, &outcome).unwrap();
        let mut prompts = 0;
        let mut pin = || {
            prompts += 1;
            Ok(enclave_core::secret::SecretBytes::new(
                b"synthetic-pin".to_vec(),
            ))
        };
        let mut captured = None;
        let pending = begin_asset_enrollment_capturing_with_pin(
            &mut CtapClient::open(&mut device).unwrap(),
            &mds,
            &active,
            disclosure,
            enclave_core::profile::Profile::L3,
            &TestClock::at(2),
            &cancelled,
            Some(&mut pin),
            |pending| {
                captured = Some(pending.digest()?);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(prompts, 1);
        assert_eq!(captured, Some(pending.digest().unwrap()));
        let evidence = super::super::cbor::decode(&pending.attestation_evidence).unwrap();
        let raw =
            super::super::cbor::bytes(super::super::cbor::tget(&evidence, "authData")).unwrap();
        assert_ne!(
            super::super::assertion::AuthenticatorData::parse(&raw)
                .unwrap()
                .flags
                & super::super::assertion::FLAG_UV,
            0
        );
    }

    #[test]
    fn independent_expiry_is_rechecked_after_getinfo_and_credential_waits() {
        use crate::{
            biometric::{BiometricPrompt, BiometricProvider, Scripted, ScriptedCoreAuthUi},
            clock::TestClock,
            ctap::{
                client::{begin_asset_enrollment_with_clock, CtapClient},
                hid::{HidDevice, CMD_CBOR, REPORT},
                mds::{MdsAllowlist, MdsEntry, MdsState},
                virtual_device::VirtualAuthenticator,
            },
        };
        #[derive(Debug)]
        struct AdvanceOnReply {
            device: VirtualAuthenticator,
            clock: TestClock,
            command: u8,
            advance: bool,
            done: bool,
        }
        impl HidDevice for AdvanceOnReply {
            fn write_report(&mut self, report: &[u8; REPORT]) -> EnclaveResult<()> {
                if report[4] == (CMD_CBOR | 0x80) && report[7] == self.command && !self.done {
                    self.advance = true;
                }
                self.device.write_report(report)
            }
            fn read_report(&mut self) -> EnclaveResult<[u8; REPORT]> {
                let report = self.device.read_report()?;
                if self.advance {
                    self.clock.advance_ms(1_000);
                    self.advance = false;
                    self.done = true;
                }
                Ok(report)
            }
            fn hub_depth(&self) -> u8 {
                self.device.hub_depth()
            }
            fn deadline_ns(&self) -> Option<u64> {
                self.device.deadline_ns()
            }
            fn set_deadline_ns(&mut self, d: Option<u64>) -> EnclaveResult<()> {
                self.device.set_deadline_ns(d)
            }
        }
        let issuer = SigningKey::from_bytes(&[9; 32]);
        let verified = verify(
            &policy(&issuer, AttestationMode::BasicWithIndependentAsset),
            &issuer,
        );
        for (command, metadata_expires, expected) in [
            (
                super::super::cmd::GET_INFO,
                1000,
                "ASSET_ENROLLMENT_SCOPE_OR_TIME",
            ),
            (
                super::super::cmd::MAKE_CREDENTIAL,
                1000,
                "ASSET_ENROLLMENT_SCOPE_OR_TIME",
            ),
            (super::super::cmd::GET_INFO, 100, "CUSTODY_METADATA_STALE"),
        ] {
            let device = VirtualAuthenticator::new([3; 16]);
            let mds = MdsState {
                refreshed_at: 1,
                expires_at: metadata_expires,
                allowlist: MdsAllowlist {
                    entries: vec![MdsEntry {
                        aaguid: hex::encode(device.aaguid),
                        description: "synthetic".into(),
                        min_firmware_version: 0x050700,
                        status_reports: vec![],
                        attestation_public_keys: vec![device.attestation_key_mds()],
                        attestation_root_certificates: vec![],
                    }],
                },
            };
            // For the metadata case the independently signed policy remains
            // current, making the earliest metadata expiry the limiting bound.
            let mut signed = policy(&issuer, AttestationMode::BasicWithIndependentAsset);
            if metadata_expires == 100 {
                signed.policy.expires_unix = 1000;
                signed.signature = issuer
                    .sign(&signed.policy.signing_message().unwrap())
                    .to_bytes()
                    .to_vec();
            }
            let active = if metadata_expires == 100 {
                verify(&signed, &issuer)
            } else {
                verified.clone()
            };
            let mut ui = ScriptedCoreAuthUi::new([Scripted::Approve]);
            let sep = ui.enrolled_key();
            let prompt = BiometricPrompt {
                localized_reason: active.localized_reason(),
                d_jcs: active.digest().to_vec(),
                nonce: vec![19; 32],
                t_start_ns: enclave_core::power::continuous_time_ns(),
                bio_key_blob: vec![],
            };
            let outcome = ui.evaluate(&prompt);
            let disclosure =
                VerifiedSetupDisclosure::verify(&active, &sep, &prompt, &outcome).unwrap();
            let clock = TestClock::at(99);
            let before = device.export_state();
            let mut wrapper = AdvanceOnReply {
                device,
                clock: clock.clone(),
                command,
                advance: false,
                done: false,
            };
            let error = begin_asset_enrollment_with_clock(
                &mut CtapClient::open(&mut wrapper).unwrap(),
                &mds,
                &active,
                disclosure,
                &clock,
            )
            .unwrap_err();
            assert!(error.is(expected), "{error:?}");
            if command == super::super::cmd::GET_INFO {
                assert_eq!(
                    wrapper.device.export_state(),
                    before,
                    "expiry before write must create no credential"
                );
            }
        }
    }
}
/// Independent asset issuer receipt, issued only after physical asset/inventory
/// verification outside the new credential's own attestation trust channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetEnrollmentReceipt {
    /// Schema version1.
    pub version: u32,
    /// Exact pending evidence digest.
    pub pending_sha256: [u8; 32],
    /// Monotonic inventory/receipt generation, durably consumed by the service.
    pub generation: u64,
    /// Inclusive issue time.
    pub issued_unix: i64,
    /// Exclusive expiry, cannot extend the policy boundary.
    pub expires_unix: i64,
    /// Raw64-byte signature over unsigned receipt message.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}
impl AssetEnrollmentReceipt {
    /// Exact issuer preimage, with signature omitted from the signed payload.
    pub fn signing_message(&self) -> EnclaveResult<Vec<u8>> {
        #[derive(Serialize)]
        struct Unsigned {
            version: u32,
            pending_sha256: [u8; 32],
            generation: u64,
            issued_unix: i64,
            expires_unix: i64,
        }
        message(
            b"MCPMac-IndependentAssetReceipt-v1\0",
            &Unsigned {
                version: self.version,
                pending_sha256: self.pending_sha256,
                generation: self.generation,
                issued_unix: self.issued_unix,
                expires_unix: self.expires_unix,
            },
        )
    }
    /// Activate only an exact pending credential under current signed policy.
    /// Caller must atomically persist receipt generation, credential and policy
    /// floors before using it, and reverify receipt/policy on subsequent boots.
    pub fn activate(
        self,
        pending: PendingAssetEnrollment,
        policy: &VerifiedAssetEnrollmentPolicy,
        inventory_issuer: &ed25519_dalek::VerifyingKey,
        minimum_generation: u64,
        now: i64,
    ) -> EnclaveResult<EnrolledCredential> {
        policy.check(&pending.credential.aaguid, now)?;
        pending
            .disclosure_evidence
            .verify(policy, &pending.sep_public_key)?;
        if pending.policy_digest != policy.digest
            || pending.mode != policy.mode()
            || self.version != 1
            || self.generation == 0
            || self.generation < minimum_generation
            || self.pending_sha256 != pending.digest()?
            || self.issued_unix < policy.policy.issued_unix
            || self.issued_unix > now
            || now >= self.expires_unix
            || self.expires_unix > policy.policy.expires_unix
        {
            fail!(EACCES, "ASSET_ENROLLMENT_RECEIPT");
        }
        signature(inventory_issuer, &self.signing_message()?, &self.signature)?;
        Ok(pending.credential)
    }
}
