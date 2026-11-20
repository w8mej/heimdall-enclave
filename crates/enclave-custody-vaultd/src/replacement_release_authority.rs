//! Inert exact-code/release-policy/scoped-grant admission for replacement Preparing.
//!
//! This is a protected embedding seam, NOT a production provider, recovery
//! signer, TUF/CTAP proof, live grant or storage API. The injected provider must
//! establish actual executing code and independently authenticated signed release
//! and scoped recovery authority. Nonzero caller hashes never establish them.
//! Parent code supplies authenticated membership/current floors and must consume
//! the checked one-use identity in the SAME anchored workflow before factors.
//! Default production startup is unchanged; no local/default provider exists.
use crate::{clock::Clock, ctap::assertion::{CredentialKey, EnrolledCredential},
    membership_retirement::RetirementIdentity,
    service::{MembershipAnchorObservation, MembershipAnchorPin}};
use enclave_core::{err, error::EnclaveResult, fail, profile::Profile};
use sha2::{Digest, Sha256};

type Hash = [u8; 32];
const MAX_INTEGER: u64 = (1 << 53) - 1;
const MAX_CODES: usize = 64;
const MAX_CANDIDATE: usize = 64 * 1024;
const NS_PER_MS: u64 = 1_000_000;

fn nonzero(value: &Hash) -> bool { *value != [0; 32] }
fn positive(value: u64) -> bool { value > 0 && value <= MAX_INTEGER }
fn normalized_key(credential: &EnrolledCredential) -> Vec<u8> {
    match &credential.key {
        CredentialKey::Ed25519(key) => key.to_edwards().compress().to_bytes().to_vec(),
        CredentialKey::Es256(key) => key.to_encoded_point(false).as_bytes().to_vec(),
    }
}

/// Exactly one protected host, or an explicitly provisioned fleet scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplacementHostFleetScope { Host(Hash), Fleet(Hash) }
impl ReplacementHostFleetScope {
    fn valid(self) -> bool { match self { Self::Host(h) | Self::Fleet(h) => nonzero(&h) } }
}
/// Distinct authorities are representable but only Preparing is admitted here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplacementReleasePurpose { MemberReplacementPreparing, OrdinaryUnlock, FleetTufPublication }

/// Independently provisioned embedding configuration; never request supplied.
#[derive(Debug)]
pub(crate) struct ReplacementReleaseConfig {
    pub(crate) membership_scope: Hash,
    pub(crate) host_or_fleet: ReplacementHostFleetScope,
    pub(crate) provider_peer_sha256: Hash,
    pub(crate) minimum_policy_revision: u64,
    pub(crate) minimum_release_version: u64,
    pub(crate) maximum_grant_lifetime_ms: u64,
}
/// Current parent-authenticated binding, not a caller's recovery claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReplacementReleaseBinding {
    pub(crate) membership_scope: Hash,
    pub(crate) owner_pin: MembershipAnchorPin,
    pub(crate) profile: Profile,
    pub(crate) boot_epoch_sha256: Hash,
    pub(crate) membership_generation: u64,
    pub(crate) proposed_workflow_attempt: u64,
    /// Exact independently authenticated saved loss statement digest.
    pub(crate) incident_sha256: Hash,
}
/// Exact identities are constructed from the parent's independently admitted
/// credentials. No Deserialize/public mutable identity or candidate hash setter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReplacementReleaseContext {
    binding: ReplacementReleaseBinding,
    survivor: RetirementIdentity,
    replacement: RetirementIdentity,
    candidate_wire_sha256: Hash,
}
impl ReplacementReleaseContext {
    pub(crate) fn new(binding: ReplacementReleaseBinding, survivor: &EnrolledCredential,
        replacement: &EnrolledCredential, candidate_wire: &[u8]) -> EnclaveResult<Self> {
        if candidate_wire.is_empty() || candidate_wire.len() > MAX_CANDIDATE {
            fail!(E2BIG, "REPLACEMENT_RELEASE_CANDIDATE_SIZE");
        }
        if survivor.credential_id == replacement.credential_id
            || (survivor.key.alg() == replacement.key.alg() && normalized_key(survivor) == normalized_key(replacement)) {
            fail!(EACCES, "REPLACEMENT_RELEASE_IDENTITY_ALIAS");
        }
        let context = Self { binding,
            survivor: RetirementIdentity::from_credential(survivor)?,
            replacement: RetirementIdentity::from_credential(replacement)?,
            candidate_wire_sha256: Sha256::digest(candidate_wire).into() };
        context.validate()?; Ok(context)
    }
    fn validate(&self) -> EnclaveResult<()> {
        let b = &self.binding;
        if ![b.membership_scope, b.owner_pin.workflow_sha256, b.boot_epoch_sha256,
            b.incident_sha256, self.candidate_wire_sha256].iter().all(nonzero)
            || !positive(b.owner_pin.revision) || b.profile == Profile::L1
            || !positive(b.membership_generation) || !positive(b.proposed_workflow_attempt)
            || b.proposed_workflow_attempt <= b.membership_generation || self.survivor == self.replacement {
            fail!(EACCES, "REPLACEMENT_RELEASE_CONTEXT");
        } Ok(())
    }
    pub(crate) fn binding(&self) -> &ReplacementReleaseBinding { &self.binding }
    pub(crate) fn survivor(&self) -> &RetirementIdentity { &self.survivor }
    pub(crate) fn replacement(&self) -> &RetirementIdentity { &self.replacement }
    pub(crate) fn candidate_wire_sha256(&self) -> Hash { self.candidate_wire_sha256 }
}
/// Floors already durably consumed in the same authoritative workflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplacementReleaseFloors {
    pub(crate) policy_revision: u64,
    pub(crate) release_version: u64,
    pub(crate) grant_generation: u64,
}
/// Immutable original request cap, including authority I/O and later factors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplacementReleaseWindow {
    original_start_ns: u64,
    boot_deadline_ns: u64,
    absolute_expiry_utc_ms: u64,
}
impl ReplacementReleaseWindow {
    pub(crate) fn original_start_ns(&self) -> u64 { self.original_start_ns }
    pub(crate) fn boot_deadline_ns(&self) -> u64 { self.boot_deadline_ns }
    pub(crate) fn absolute_expiry_utc_ms(&self) -> u64 { self.absolute_expiry_utc_ms }
    pub(crate) fn new(original_start_ns: u64, earlier_boot_deadline_ns: Option<u64>,
        absolute_expiry_utc_ms: u64) -> EnclaveResult<Self> {
        let cap = original_start_ns.checked_add(crate::ceremony::CEREMONY_BUDGET_NS)
            .ok_or_else(|| err!(ETIMEDOUT, "REPLACEMENT_RELEASE_DEADLINE"))?;
        let window = Self { original_start_ns,
            boot_deadline_ns: earlier_boot_deadline_ns.map_or(cap, |earlier| earlier.min(cap)),
            absolute_expiry_utc_ms };
        if !positive(absolute_expiry_utc_ms) || window.boot_deadline_ns <= original_start_ns {
            fail!(EACCES, "REPLACEMENT_RELEASE_WINDOW");
        } Ok(window)
    }
    fn check(self, now_ns: u64) -> EnclaveResult<()> {
        if now_ns < self.original_start_ns || now_ns >= self.boot_deadline_ns {
            fail!(ETIMEDOUT, "REPLACEMENT_RELEASE_DEADLINE");
        } Ok(())
    }
}
/// Entire fresh challenge must be authenticated by the provider's response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReplacementReleaseRequest {
    pub(crate) nonce: Hash,
    pub(crate) host_or_fleet: ReplacementHostFleetScope,
    pub(crate) purpose: ReplacementReleasePurpose,
    pub(crate) context: ReplacementReleaseContext,
    pub(crate) floors: ReplacementReleaseFloors,
    pub(crate) window: ReplacementReleaseWindow,
}
/// Conservative independently authenticated inclusive UTC uncertainty range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplacementTrustedInterval { pub(crate) lower_utc_ms: u64, pub(crate) upper_utc_ms: u64 }
impl ReplacementTrustedInterval {
    fn validate(self) -> EnclaveResult<()> {
        if !positive(self.lower_utc_ms) || self.lower_utc_ms > self.upper_utc_ms
            || self.upper_utc_ms > MAX_INTEGER || self.upper_utc_ms - self.lower_utc_ms > 1000 {
            fail!(EACCES, "REPLACEMENT_RELEASE_TIME");
        } Ok(())
    }
}
/// Signed document validity authenticated by the protected provider.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReplacementDocumentValidity {
    pub(crate) issued_utc_ms: u64, pub(crate) not_before_utc_ms: u64, pub(crate) expires_utc_ms: u64,
}
impl ReplacementDocumentValidity {
    fn validate(self, interval: ReplacementTrustedInterval) -> EnclaveResult<()> {
        if self.issued_utc_ms > self.not_before_utc_ms || self.not_before_utc_ms >= self.expires_utc_ms
            || self.expires_utc_ms > MAX_INTEGER || interval.lower_utc_ms < self.not_before_utc_ms
            || interval.upper_utc_ms >= self.expires_utc_ms {
            fail!(EACCES, "REPLACEMENT_RELEASE_DOCUMENT_TIME");
        } Ok(())
    }
}
/// Facts authenticated by a real adapter, not raw caller-supplied wire fields.
#[derive(Debug)]
pub(crate) struct ReplacementReleaseObservation {
    pub(crate) request: ReplacementReleaseRequest,
    pub(crate) provider_peer_sha256: Hash,
    pub(crate) trusted: ReplacementTrustedInterval,
    pub(crate) running_code_sha256: Hash,
    pub(crate) approved_code_sha256: Vec<Hash>,
    pub(crate) release_policy_sha256: Hash,
    pub(crate) release_policy_revision: u64,
    /// Ordered signed version counter. Code hashes themselves have NO order.
    pub(crate) release_version: u64,
    pub(crate) release_policy_validity: ReplacementDocumentValidity,
    pub(crate) grant_id: Hash,
    pub(crate) grant_generation: u64,
    pub(crate) grant_validity: ReplacementDocumentValidity,
    pub(crate) transport_expires_utc_ms: u64,
    pub(crate) transport_boot_deadline_ns: Option<u64>,
}
/// Protected adapter contract. Implementations MUST freshly authenticate both
/// peers and nonce, MEASURE the actual executing code, verify independent signed
/// release/version policy and exact code-hash membership, and authenticate a
/// separate scoped replacement grant covering the ENTIRE request AND returned
/// code/policy/version/grant facts. Local hash files, request echoes, inventory
/// signatures, CTAP facts, TUF signatures and ordinary unlock are not substitutes.
/// The provider must bound request lifetime and authenticate trusted time.
/// Observation does not consume the one-use grant: parent must atomically burn
/// grant ID+generation with candidate and floors in the same anchored workflow.
/// No production implementation, issuer roster or test fallback is supplied.
pub(crate) trait ReplacementReleaseProvider: Send {
    fn observe(&mut self, request: &ReplacementReleaseRequest) -> EnclaveResult<ReplacementReleaseObservation>;
}
/// Protected embedding owner. No Deserialize/Clone/default/RPC constructor.
pub(crate) struct ReplacementReleaseAuthority {
    config: ReplacementReleaseConfig, provider: Box<dyn ReplacementReleaseProvider>,
}
impl std::fmt::Debug for ReplacementReleaseAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplacementReleaseAuthority").finish_non_exhaustive()
    }
}
/// Move-only checked facts, inert until parent SAME-workflow Preparing consumes
/// them. No activation, factor, release, persistence or mutable authority API.
#[derive(Debug)]
pub(crate) struct CheckedReplacementRelease {
    request: ReplacementReleaseRequest,
    running_code_sha256: Hash, release_policy_sha256: Hash,
    release_policy_revision: u64, release_version: u64, release_policy_expires_utc_ms: u64,
    grant_id: Hash, grant_generation: u64, grant_expires_utc_ms: u64,
    trusted: ReplacementTrustedInterval, valid_before_utc_ms: u64, boot_deadline_ns: u64,
}
impl CheckedReplacementRelease {
    pub(crate) fn context(&self) -> &ReplacementReleaseContext { &self.request.context }
    pub(crate) fn request(&self) -> &ReplacementReleaseRequest { &self.request }
    pub(crate) fn running_code_sha256(&self) -> Hash { self.running_code_sha256 }
    pub(crate) fn release_policy_sha256(&self) -> Hash { self.release_policy_sha256 }
    pub(crate) fn release_policy_revision(&self) -> u64 { self.release_policy_revision }
    pub(crate) fn release_version(&self) -> u64 { self.release_version }
    pub(crate) fn release_policy_expires_utc_ms(&self) -> u64 { self.release_policy_expires_utc_ms }
    pub(crate) fn grant_id(&self) -> Hash { self.grant_id }
    pub(crate) fn grant_generation(&self) -> u64 { self.grant_generation }
    pub(crate) fn grant_expires_utc_ms(&self) -> u64 { self.grant_expires_utc_ms }
    pub(crate) fn trusted_interval(&self) -> ReplacementTrustedInterval { self.trusted }
    pub(crate) fn valid_before_utc_ms(&self) -> u64 { self.valid_before_utc_ms }
    pub(crate) fn boot_deadline_ns(&self) -> u64 { self.boot_deadline_ns }
    /// Pure original-window check only; not a fresh provider/head revalidation.
    pub(crate) fn check_at_boot(&self, now_ns: u64) -> EnclaveResult<()> {
        self.request.window.check(now_ns)?;
        if now_ns >= self.boot_deadline_ns { fail!(ETIMEDOUT, "REPLACEMENT_RELEASE_DEADLINE"); } Ok(())
    }
}
impl ReplacementReleaseAuthority {
    pub(crate) fn new(config: ReplacementReleaseConfig, provider: Option<Box<dyn ReplacementReleaseProvider>>) -> EnclaveResult<Self> {
        if !nonzero(&config.membership_scope) || !config.host_or_fleet.valid() || !nonzero(&config.provider_peer_sha256)
            || !positive(config.minimum_policy_revision) || !positive(config.minimum_release_version)
            || config.maximum_grant_lifetime_ms == 0 || config.maximum_grant_lifetime_ms > 10_000 {
            fail!(EACCES, "REPLACEMENT_RELEASE_CONFIG");
        }
        Ok(Self { config, provider: provider.ok_or_else(|| err!(EACCES, "REPLACEMENT_RELEASE_PROVIDER_REQUIRED"))? })
    }
    /// Parent must pass a fresh observation ALREADY authenticated by its
    /// mandatory membership owner, with the exact current pin/floors/context.
    /// This module checks consistency; it cannot authenticate an invented one.
    pub(crate) fn check(&mut self, context: &ReplacementReleaseContext, floors: ReplacementReleaseFloors,
        membership: MembershipAnchorObservation, window: ReplacementReleaseWindow,
        clock: &dyn Clock) -> EnclaveResult<CheckedReplacementRelease> {
        context.validate()?;
        let before = clock.now_ns(); window.check(before)?;
        if context.binding.membership_scope != self.config.membership_scope
            || membership.scope != self.config.membership_scope || membership.pin != context.binding.owner_pin
            || !nonzero(&membership.peer_sha256) || !nonzero(&membership.nonce)
            || [floors.policy_revision, floors.release_version, floors.grant_generation].iter().any(|n| *n > MAX_INTEGER) {
            fail!(EACCES, "REPLACEMENT_RELEASE_MEMBERSHIP");
        }
        let membership_time = ReplacementTrustedInterval { lower_utc_ms: membership.trusted_lower_utc_ms,
            upper_utc_ms: membership.trusted_upper_utc_ms }; membership_time.validate()?;
        let nonce = enclave_core::rng::bytes32();
        if !nonzero(&nonce) { fail!(EIO, "REPLACEMENT_RELEASE_NONCE"); }
        let request = ReplacementReleaseRequest { nonce, host_or_fleet: self.config.host_or_fleet,
            purpose: ReplacementReleasePurpose::MemberReplacementPreparing, context: context.clone(), floors, window };
        let observed = self.provider.observe(&request)?;
        let after = clock.now_ns(); window.check(after)?;
        if after < before { fail!(ETIMEDOUT, "REPLACEMENT_RELEASE_DEADLINE"); }
        if observed.request != request || observed.provider_peer_sha256 != self.config.provider_peer_sha256 {
            fail!(EACCES, "REPLACEMENT_RELEASE_RESPONSE_BINDING");
        }
        observed.trusted.validate()?;
        let trusted = ReplacementTrustedInterval {
            lower_utc_ms: membership_time.lower_utc_ms.max(observed.trusted.lower_utc_ms),
            upper_utc_ms: membership_time.upper_utc_ms.min(observed.trusted.upper_utc_ms) };
        // Disjoint intervals refuse, rather than widening either authority.
        trusted.validate()?;
        let codes = &observed.approved_code_sha256;
        if !nonzero(&observed.running_code_sha256) || codes.is_empty() || codes.len() > MAX_CODES
            || codes.iter().any(|h| !nonzero(h)) || codes.iter().enumerate().any(|(i, h)| codes[..i].contains(h))
            || !codes.contains(&observed.running_code_sha256) || !nonzero(&observed.release_policy_sha256)
            || !positive(observed.release_policy_revision) || !positive(observed.release_version)
            || observed.release_policy_revision < self.config.minimum_policy_revision.max(floors.policy_revision)
            || observed.release_version < self.config.minimum_release_version.max(floors.release_version)
            || !nonzero(&observed.grant_id) || !positive(observed.grant_generation)
            || observed.grant_generation <= floors.grant_generation {
            fail!(EACCES, "REPLACEMENT_RELEASE_CODE_POLICY_OR_GRANT");
        }
        observed.release_policy_validity.validate(trusted)?; observed.grant_validity.validate(trusted)?;
        if observed.grant_validity.expires_utc_ms - observed.grant_validity.issued_utc_ms > self.config.maximum_grant_lifetime_ms
            || !positive(observed.transport_expires_utc_ms) {
            fail!(EACCES, "REPLACEMENT_RELEASE_DOCUMENT_TIME");
        }
        // The original independently observed lower endpoint + remaining
        // ORIGINAL boot budget is conservative even if provider I/O was slow.
        let remaining_ms = (window.boot_deadline_ns - after) / NS_PER_MS;
        let original_cutoff = membership_time.lower_utc_ms.checked_add(remaining_ms)
            .filter(|end| *end <= MAX_INTEGER).ok_or_else(|| err!(EACCES, "REPLACEMENT_RELEASE_TIME"))?;
        let until = [original_cutoff, window.absolute_expiry_utc_ms, observed.release_policy_validity.expires_utc_ms,
            observed.grant_validity.expires_utc_ms, observed.transport_expires_utc_ms].into_iter().min().unwrap();
        if trusted.upper_utc_ms >= until { fail!(ETIMEDOUT, "REPLACEMENT_RELEASE_DEADLINE"); }
        // Membership time may have been authenticated before this module was
        // called. Map from the immutable request start, before membership and
        // all parent/provider I/O. Even `before` would add parent I/O elapsed
        // since the older membership observation to an earlier signed expiry.
        let delta = (until - trusted.upper_utc_ms).checked_mul(NS_PER_MS)
            .ok_or_else(|| err!(EACCES, "REPLACEMENT_RELEASE_TIME"))?;
        let mapped = window.original_start_ns.checked_add(delta).ok_or_else(|| err!(EACCES, "REPLACEMENT_RELEASE_TIME"))?;
        let deadline = [Some(window.boot_deadline_ns), Some(mapped), observed.transport_boot_deadline_ns]
            .into_iter().flatten().min().unwrap();
        if after >= deadline { fail!(ETIMEDOUT, "REPLACEMENT_RELEASE_DEADLINE"); }
        Ok(CheckedReplacementRelease { request, running_code_sha256: observed.running_code_sha256,
            release_policy_sha256: observed.release_policy_sha256, release_policy_revision: observed.release_policy_revision,
            release_version: observed.release_version, release_policy_expires_utc_ms: observed.release_policy_validity.expires_utc_ms,
            grant_id: observed.grant_id, grant_generation: observed.grant_generation,
            grant_expires_utc_ms: observed.grant_validity.expires_utc_ms, trusted, valid_before_utc_ms: until,
            boot_deadline_ns: deadline })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex, atomic::{AtomicU64, Ordering}};

    #[derive(Debug, Clone)]
    struct TestBoot(Arc<AtomicU64>);
    impl Clock for TestBoot {
        fn now_ns(&self) -> u64 { self.0.load(Ordering::SeqCst) }
        fn now_unix(&self) -> i64 { panic!("Host wall time must never supply replacement authority") }
    }
    type Observe = Box<dyn FnMut(&ReplacementReleaseRequest) -> EnclaveResult<ReplacementReleaseObservation> + Send>;
    struct Provider(Observe);
    impl ReplacementReleaseProvider for Provider {
        fn observe(&mut self, request: &ReplacementReleaseRequest) -> EnclaveResult<ReplacementReleaseObservation> { self.0(request) }
    }
    fn credential(id: u8, key: u8) -> EnrolledCredential {
        EnrolledCredential { credential_id: vec![id], key: CredentialKey::Ed25519(
            ed25519_dalek::SigningKey::from_bytes(&[key; 32]).verifying_key()), aaguid: [7; 16], firmware_version: 1 }
    }
    fn context() -> ReplacementReleaseContext {
        ReplacementReleaseContext::new(ReplacementReleaseBinding { membership_scope: [1; 32],
            owner_pin: MembershipAnchorPin { revision: 7, workflow_sha256: [2; 32] }, profile: Profile::L3,
            boot_epoch_sha256: [3; 32], membership_generation: 4, proposed_workflow_attempt: 6,
            incident_sha256: [4; 32] }, &credential(1, 1), &credential(2, 2), b"exact signed candidate wire").unwrap()
    }
    fn config() -> ReplacementReleaseConfig { ReplacementReleaseConfig { membership_scope: [1; 32],
        host_or_fleet: ReplacementHostFleetScope::Host([5; 32]), provider_peer_sha256: [6; 32],
        minimum_policy_revision: 3, minimum_release_version: 5, maximum_grant_lifetime_ms: 10_000 } }
    fn floors() -> ReplacementReleaseFloors { ReplacementReleaseFloors { policy_revision: 2, release_version: 4, grant_generation: 8 } }
    fn membership() -> MembershipAnchorObservation { MembershipAnchorObservation { scope: [1; 32], peer_sha256: [90; 32], nonce: [91; 32],
        pin: context().binding.owner_pin, trusted_lower_utc_ms: 100_000, trusted_upper_utc_ms: 100_100 } }
    fn window() -> ReplacementReleaseWindow { ReplacementReleaseWindow::new(1_000_000_000, None, 120_000).unwrap() }
    fn clock() -> TestBoot { TestBoot(Arc::new(AtomicU64::new(1_000_000_000))) }
    fn validity() -> ReplacementDocumentValidity { ReplacementDocumentValidity { issued_utc_ms: 99_000, not_before_utc_ms: 99_500, expires_utc_ms: 108_000 } }
    fn response(request: &ReplacementReleaseRequest) -> ReplacementReleaseObservation {
        ReplacementReleaseObservation { request: request.clone(), provider_peer_sha256: [6; 32],
            trusted: ReplacementTrustedInterval { lower_utc_ms: 100_050, upper_utc_ms: 100_150 },
            running_code_sha256: [7; 32], approved_code_sha256: vec![[8; 32], [7; 32]], release_policy_sha256: [9; 32],
            release_policy_revision: 3, release_version: 5, release_policy_validity: ReplacementDocumentValidity { expires_utc_ms: 115_000, ..validity() },
            grant_id: [10; 32], grant_generation: 9, grant_validity: validity(), transport_expires_utc_ms: 114_000,
            transport_boot_deadline_ns: None }
    }
    fn authority(edit: impl FnMut(&mut ReplacementReleaseObservation) + Send + 'static) -> ReplacementReleaseAuthority {
        let mut edit = edit;
        ReplacementReleaseAuthority::new(config(), Some(Box::new(Provider(Box::new(move |r| {
            let mut observed = response(r); edit(&mut observed); Ok(observed)
        }))))).unwrap()
    }
    fn checked(edit: impl FnMut(&mut ReplacementReleaseObservation) + Send + 'static) -> EnclaveResult<CheckedReplacementRelease> {
        authority(edit).check(&context(), floors(), membership(), window(), &clock())
    }

    #[test]
    fn actual_adapter_checks_exact_code_membership_and_retains_all_inert_facts_for_host_or_explicit_fleet() {
        for scope in [ReplacementHostFleetScope::Host([5; 32]), ReplacementHostFleetScope::Fleet([5; 32])] {
            let mut cfg = config(); cfg.host_or_fleet = scope;
            let mut owner = ReplacementReleaseAuthority::new(cfg, Some(Box::new(Provider(Box::new(|r| Ok(response(r))))))).unwrap();
            let value = owner.check(&context(), floors(), membership(), window(), &clock()).unwrap();
            assert_eq!(value.request().host_or_fleet, scope); assert_eq!(value.context(), &context());
            assert_eq!(value.context().survivor(), &RetirementIdentity::from_credential(&credential(1, 1)).unwrap());
            assert_eq!(value.context().replacement(), &RetirementIdentity::from_credential(&credential(2, 2)).unwrap());
            assert_eq!(value.context().binding().proposed_workflow_attempt, 6);
            let wire_hash: Hash = Sha256::digest(b"exact signed candidate wire").into();
            assert_eq!(value.context().candidate_wire_sha256(), wire_hash);
            assert_eq!(value.running_code_sha256(), [7; 32]); assert_eq!(value.release_policy_sha256(), [9; 32]);
            assert_eq!((value.release_policy_revision(), value.release_version()), (3, 5));
            assert_eq!(value.release_policy_expires_utc_ms(), 115_000);
            assert_eq!((value.grant_id(), value.grant_generation(), value.grant_expires_utc_ms()), ([10; 32], 9, 108_000));
            assert_eq!(value.trusted_interval(), ReplacementTrustedInterval { lower_utc_ms: 100_050, upper_utc_ms: 100_100 });
            assert_eq!(value.valid_before_utc_ms(), 108_000); assert_eq!(value.boot_deadline_ns(), 8_900_000_000);
            value.check_at_boot(value.boot_deadline_ns() - 1).unwrap();
            assert!(value.check_at_boot(value.boot_deadline_ns()).is_err());
        }
    }
    #[test]
    fn wrong_nonce_peer_purpose_host_fleet_and_every_exact_context_or_floor_echo_refuse() {
        for mode in 0..21 {
            assert!(checked(move |o| match mode {
                0 => o.request.nonce[0] ^= 1, 1 => o.provider_peer_sha256[0] ^= 1,
                2 => o.request.purpose = ReplacementReleasePurpose::OrdinaryUnlock,
                3 => o.request.purpose = ReplacementReleasePurpose::FleetTufPublication,
                4 => o.request.host_or_fleet = ReplacementHostFleetScope::Fleet([5; 32]),
                5 => o.request.context.binding.membership_scope[0] ^= 1,
                6 => o.request.context.binding.owner_pin.revision += 1,
                7 => o.request.context.binding.owner_pin.workflow_sha256[0] ^= 1,
                8 => o.request.context.binding.boot_epoch_sha256[0] ^= 1,
                9 => o.request.context.binding.incident_sha256[0] ^= 1,
                10 => o.request.context.binding.membership_generation += 1,
                11 => o.request.context.binding.proposed_workflow_attempt += 1,
                12 => o.request.context.binding.profile = Profile::L2,
                13 => o.request.context.survivor = RetirementIdentity::from_credential(&credential(3, 3)).unwrap(),
                14 => o.request.context.replacement = RetirementIdentity::from_credential(&credential(3, 3)).unwrap(),
                15 => o.request.context.candidate_wire_sha256[0] ^= 1,
                16 => o.request.floors.grant_generation += 1,
                17 => o.request.window.boot_deadline_ns += 1,
                18 => o.request.floors.policy_revision += 1,
                19 => o.request.floors.release_version += 1,
                _ => o.request.window.original_start_ns += 1,
            }).unwrap_err().is("REPLACEMENT_RELEASE_RESPONSE_BINDING"));
        }
    }
    #[test]
    fn code_allowlist_signed_policy_versions_and_unconsumed_grant_generation_are_strictly_checked() {
        for mode in 0..17 {
            assert!(checked(move |o| match mode {
                0 => o.running_code_sha256 = [0; 32], 1 => o.running_code_sha256 = [44; 32],
                2 => o.approved_code_sha256.clear(), 3 => o.approved_code_sha256.push([7; 32]),
                4 => o.approved_code_sha256.push([0; 32]), 5 => o.approved_code_sha256 = vec![[7; 32]; 65],
                6 => o.release_policy_sha256 = [0; 32], 7 => o.release_policy_revision = 2,
                8 => o.release_policy_revision = MAX_INTEGER + 1, 9 => o.release_version = 4,
                10 => o.release_version = MAX_INTEGER + 1, 11 => o.grant_id = [0; 32],
                12 => o.grant_generation = 8, 13 => o.grant_generation = MAX_INTEGER + 1,
                14 => o.release_policy_revision = 0, 15 => o.release_version = 0, _ => o.grant_generation = 0,
            }).unwrap_err().is("REPLACEMENT_RELEASE_CODE_POLICY_OR_GRANT"));
        }
        let mut newer = floors(); newer.policy_revision = 4;
        assert!(authority(|_| {}).check(&context(), newer, membership(), window(), &clock()).is_err());
        newer = floors(); newer.release_version = 6;
        assert!(authority(|_| {}).check(&context(), newer, membership(), window(), &clock()).is_err());
        newer = floors(); newer.grant_generation = 9;
        assert!(authority(|_| {}).check(&context(), newer, membership(), window(), &clock()).is_err());
    }
    #[test]
    fn trusted_membership_and_provider_intervals_intersect_and_never_widen_disjoint_or_malformed_ranges() {
        for (lower, upper) in [(100_101, 100_150), (99_900, 99_999), (0, 100), (100_200, 100_100),
            (100_000, 101_001), (MAX_INTEGER, MAX_INTEGER + 1)] {
            assert!(checked(move |o| o.trusted = ReplacementTrustedInterval { lower_utc_ms: lower, upper_utc_ms: upper }).is_err());
        }
        let edge = checked(|o| o.trusted = ReplacementTrustedInterval { lower_utc_ms: 100_100, upper_utc_ms: 100_150 }).unwrap();
        assert_eq!(edge.trusted_interval(), ReplacementTrustedInterval { lower_utc_ms: 100_100, upper_utc_ms: 100_100 });
        for mode in 0..5 {
            let mut m = membership(); match mode { 0 => m.trusted_lower_utc_ms = 0,
                1 => m.trusted_lower_utc_ms = 100_101, 2 => m.trusted_upper_utc_ms = 101_001,
                3 => m.trusted_upper_utc_ms = MAX_INTEGER + 1, _ => m.pin.revision += 1 }
            assert!(authority(|_| {}).check(&context(), floors(), m, window(), &clock()).is_err());
        }
    }
    #[test]
    fn every_independent_expiry_and_earlier_boot_cutoff_bounds_checked_facts() {
        for mode in 0..4 {
            let mut w = window(); if mode == 0 { w.absolute_expiry_utc_ms = 103_000; }
            let mut owner = authority(move |o| match mode { 1 => o.release_policy_validity.expires_utc_ms = 103_000,
                2 => o.grant_validity.expires_utc_ms = 103_000, 3 => o.transport_expires_utc_ms = 103_000, _ => {} });
            let v = owner.check(&context(), floors(), membership(), w, &clock()).unwrap();
            assert_eq!(v.valid_before_utc_ms(), 103_000); assert_eq!(v.boot_deadline_ns(), 3_900_000_000);
        }
        let v = checked(|o| o.transport_boot_deadline_ns = Some(2_000_000_000)).unwrap();
        assert_eq!(v.boot_deadline_ns(), 2_000_000_000);
        let w = ReplacementReleaseWindow::new(1_000_000_000, Some(2_000_000_000), 120_000).unwrap();
        let v = authority(|_| {}).check(&context(), floors(), membership(), w, &clock()).unwrap();
        assert_eq!(v.valid_before_utc_ms(), 101_000); assert_eq!(v.boot_deadline_ns(), 1_900_000_000);
    }
    #[test]
    fn document_expiry_notbefore_lifetime_and_safe_integer_shapes_refuse_at_inclusive_upper_boundary() {
        for mode in 0..12 {
            assert!(checked(move |o| match mode {
                0 => o.release_policy_validity.expires_utc_ms = 100_100,
                1 => o.grant_validity.expires_utc_ms = 100_100,
                2 => o.release_policy_validity.not_before_utc_ms = 100_051,
                3 => o.grant_validity.not_before_utc_ms = 100_051,
                4 => o.grant_validity.issued_utc_ms = 99_501,
                5 => o.grant_validity.expires_utc_ms = 110_001,
                6 => o.release_policy_validity.expires_utc_ms = MAX_INTEGER + 1,
                7 => o.grant_validity.expires_utc_ms = MAX_INTEGER + 1,
                8 => o.transport_expires_utc_ms = 0,
                9 => o.transport_expires_utc_ms = MAX_INTEGER + 1,
                10 => o.transport_expires_utc_ms = 100_100,
                _ => o.transport_boot_deadline_ns = Some(1_000_000_000),
            }).is_err());
        }
    }
    #[test]
    fn original_ten_second_window_cannot_restart_and_slow_provider_never_extends_absolute_mapping() {
        let seen = Arc::new(AtomicU64::new(0)); let called = seen.clone();
        let mut owner = ReplacementReleaseAuthority::new(config(), Some(Box::new(Provider(Box::new(move |r| {
            called.fetch_add(1, Ordering::SeqCst); Ok(response(r))
        }))))).unwrap();
        let c = clock(); c.0.store(11_000_000_000, Ordering::SeqCst);
        assert!(owner.check(&context(), floors(), membership(), window(), &c).is_err()); assert_eq!(seen.load(Ordering::SeqCst), 0);
        c.0.store(999_999_999, Ordering::SeqCst);
        assert!(owner.check(&context(), floors(), membership(), window(), &c).is_err());
        assert!(ReplacementReleaseWindow::new(u64::MAX, None, 120_000).is_err());
        for after in [3_000_000_000, 11_000_000_000, 999_999_999] {
            let c = clock(); let moved = c.clone();
            let mut owner = ReplacementReleaseAuthority::new(config(), Some(Box::new(Provider(Box::new(move |r| {
                moved.0.store(after, Ordering::SeqCst); Ok(response(r))
            }))))).unwrap();
            let result = owner.check(&context(), floors(), membership(), window(), &c);
            if after == 3_000_000_000 {
                let v = result.unwrap(); assert_eq!(v.boot_deadline_ns(), 8_900_000_000,
                    "mapping from return would improperly add two seconds to earlier expiry");
                assert_eq!(v.request().window.original_start_ns, 1_000_000_000);
            } else { assert!(result.is_err()); }
        }
    }
    #[test]
    fn delayed_parent_io_cannot_extend_expiry_observed_before_adapter_entry() {
        for before in [2_000_000_000, 4_000_000_000] {
            let c = clock(); c.0.store(before, Ordering::SeqCst);
            let mut owner = authority(|o| o.transport_expires_utc_ms = 102_100);
            let result = owner.check(&context(), floors(), membership(), window(), &c);
            if before == 2_000_000_000 {
                let value = result.unwrap();
                assert_eq!(value.valid_before_utc_ms(), 102_100);
                assert_eq!(value.boot_deadline_ns(), 3_000_000_000,
                    "old membership time maps from original1s start, never delayed2s entry");
                value.check_at_boot(2_999_999_999).unwrap();
                assert!(value.check_at_boot(3_000_000_000).is_err());
            } else {
                assert!(result.unwrap_err().is("REPLACEMENT_RELEASE_DEADLINE"),
                    "parent I/O already consumed the signed short-expiry window");
            }
        }
    }
    #[test]
    fn absent_provider_errors_cached_nonce_and_bad_context_refuse_without_a_local_fallback() {
        assert!(ReplacementReleaseAuthority::new(config(), None).unwrap_err().is("REPLACEMENT_RELEASE_PROVIDER_REQUIRED"));
        let mut cfg = config(); cfg.maximum_grant_lifetime_ms = 10_001;
        assert!(ReplacementReleaseAuthority::new(cfg, None).unwrap_err().is("REPLACEMENT_RELEASE_CONFIG"));
        let cache = Arc::new(Mutex::new(None::<ReplacementReleaseRequest>)); let copy = cache.clone();
        let mut owner = ReplacementReleaseAuthority::new(config(), Some(Box::new(Provider(Box::new(move |r| {
            let mut prior = copy.lock().unwrap(); let observed = response(prior.as_ref().unwrap_or(r));
            if prior.is_none() { *prior = Some(r.clone()); } Ok(observed)
        }))))).unwrap();
        owner.check(&context(), floors(), membership(), window(), &clock()).unwrap();
        assert!(owner.check(&context(), floors(), membership(), window(), &clock()).unwrap_err().is("REPLACEMENT_RELEASE_RESPONSE_BINDING"));
        let mut owner = ReplacementReleaseAuthority::new(config(), Some(Box::new(Provider(Box::new(|_| {
            Err(err!(EIO, "SYNTHETIC_RELEASE_PROVIDER_FAILURE"))
        }))))).unwrap();
        assert!(owner.check(&context(), floors(), membership(), window(), &clock()).unwrap_err().is("SYNTHETIC_RELEASE_PROVIDER_FAILURE"));
        for mode in 0..8 {
            let mut b = context().binding().clone(); match mode { 0 => b.membership_scope = [0; 32],
                1 => b.owner_pin.revision = MAX_INTEGER + 1, 2 => b.profile = Profile::L1,
                3 => b.boot_epoch_sha256 = [0; 32], 4 => b.membership_generation = 0,
                5 => b.proposed_workflow_attempt = b.membership_generation, 6 => b.incident_sha256 = [0; 32],
                _ => b.owner_pin.workflow_sha256 = [0; 32] }
            assert!(ReplacementReleaseContext::new(b, &credential(1, 1), &credential(2, 2), b"candidate").is_err());
        }
        assert!(ReplacementReleaseContext::new(context().binding().clone(), &credential(1, 1), &credential(1, 2), b"candidate").is_err());
        assert!(ReplacementReleaseContext::new(context().binding().clone(), &credential(1, 1), &credential(2, 1), b"candidate").is_err());
        assert!(ReplacementReleaseContext::new(context().binding().clone(), &credential(1, 1), &credential(2, 2), b"").is_err());
    }
}
