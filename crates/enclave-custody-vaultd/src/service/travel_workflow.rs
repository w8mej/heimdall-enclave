//! Explicit bounded travel exception; the configured profile remains L3.
//! Every production provider must be independently provisioned. No local file
//! implements the external anchor or supplies trusted current time.
use super::*;
use std::path::{Path, PathBuf};

#[cfg(test)]
std::thread_local! {
    pub(super) static AFTER_PREFLIGHT:std::cell::RefCell<Option<Box<dyn FnOnce()>>>=std::cell::RefCell::new(None);
}
#[cfg(test)]
pub(super) fn after_preflight_for_test() {
    let hook = AFTER_PREFLIGHT.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

/// Exact independently retained complete travel-journal commitment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TravelAnchorPin {
    /// Strictly increasing generation; zero is uninitialized genesis only.
    pub generation: u64,
    /// SHA256 of the complete canonical journal, including consumed tokens.
    pub journal_sha256: [u8; 32],
}
/// Authenticated external state plus conservative current wall-clock bounds.
/// The provider must authenticate a fresh nonce-bound observation, not replay a
/// cached signed receipt. The interval may be at most one second wide.
#[derive(Debug, Clone, Copy)]
pub struct TravelAnchorObservation {
    /// Independently retained exact current state.
    pub pin: TravelAnchorPin,
    /// Authenticated lower bound on current Unix milliseconds.
    pub trusted_lower_utc_ms: u64,
    /// Authenticated upper bound on current Unix milliseconds.
    pub trusted_upper_utc_ms: u64,
}
/// Independently isolated durable linearizable state and current-time service.
/// Implementations pin the exact scope independently, survive local root/disk
/// restoration, authenticate both peers, and bound request lifetime. A CAS
/// failure may have applied: callers latch closed and reconcile on reopen.
/// A second file, local helper flag or caller-supplied receipt cannot implement
/// this authority. No production implementation is supplied by this module.
pub trait TravelRecoveryAnchor: Send {
    /// Load a fresh authenticated exact scope and current time observation.
    fn load(&mut self, scope: [u8; 32]) -> EnclaveResult<TravelAnchorObservation>;
    /// Durably compare-and-advance this exact scope, returning fresh time.
    /// If supplied, `valid_before_utc_ms` must be enforced atomically BEFORE
    /// applying the new pin; expired/unknown time must leave the pin unchanged.
    fn compare_and_advance(
        &mut self,
        scope: [u8; 32],
        expected: TravelAnchorPin,
        next: TravelAnchorPin,
        valid_before_utc_ms: Option<u64>,
    ) -> EnclaveResult<TravelAnchorObservation>;
}
/// Protected administrator-provisioned travel trust. None of these values may
/// be taken from the submitted token. Production deployment must supply the
/// independent anchor separately and preserve the permanent L3 floor.
#[derive(Clone)]
pub struct TravelAuthorityConfig {
    /// Independently configured issuer identity.
    pub issuer_id: String,
    /// Independently installed issuer public key.
    pub issuer: VerifyingKey,
    /// Exact fixed workstation subject.
    pub subject_spiffe_id: String,
    /// Exact fixed device identity.
    pub device_serial: String,
    /// Required distinct SecOps threshold, at least two.
    pub threshold: usize,
    /// Finite current authority freshness ceiling, at most72h.
    pub maximum_authority_age_ms: u64,
    /// Protected independently issuer-signed roster path, reread at each use.
    pub roster_file: PathBuf,
}
impl std::fmt::Debug for TravelAuthorityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TravelAuthorityConfig")
            .field("threshold", &self.threshold)
            .finish_non_exhaustive()
    }
}
impl TravelAuthorityConfig {
    pub(crate) fn pins(&self) -> EnclaveResult<crate::travel_recovery::TravelAuthorityPins> {
        crate::travel_recovery::TravelAuthorityPins::new(
            self.issuer_id.clone(),
            self.issuer,
            self.subject_spiffe_id.clone(),
            self.device_serial.clone(),
            self.threshold,
            self.maximum_authority_age_ms,
        )
    }
    pub(super) fn read_roster(&self) -> EnclaveResult<Vec<u8>> {
        read_asset_authority_file(&self.roster_file, 128 * 1024)
    }
}

/// Opaque verified travel bootstrap. Possession alone does not activate a
/// profile: startup must still verify the current original membership/content,
/// policy, actual audit prefix, external anchor and earliest expiry.
pub struct ValidatedTravelStartup {
    pub(super) authority: TravelAuthorityConfig,
    pub(super) store: crate::travel_recovery::TravelRecoveryStore,
    pub(super) session: crate::travel_recovery::TravelSession,
    audit_path: PathBuf,
}
impl std::fmt::Debug for ValidatedTravelStartup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatedTravelStartup")
            .finish_non_exhaustive()
    }
}

/// Verify the externally anchored existing active transition before touching a
/// native authenticator. Missing authority/time/anchor/audit refuses bootstrap;
/// this function never creates a new active transition or live ceremony grant.
pub fn load_travel_startup(
    state: &Path,
    authority: TravelAuthorityConfig,
    anchor: Box<dyn TravelRecoveryAnchor>,
    audit_path: &Path,
    original_scope: [u8; 32],
) -> EnclaveResult<ValidatedTravelStartup> {
    let mut store = crate::travel_recovery::TravelRecoveryStore::open_anchored(
        state,
        authority.pins()?,
        original_scope,
        anchor,
    )?;
    let mut source = || authority.read_roster();
    let session = store.current_service_session(
        original_scope,
        &mut source,
        &SystemClock::default(),
        audit_path,
    )?;
    Ok(ValidatedTravelStartup {
        authority,
        store,
        session,
        audit_path: audit_path.to_owned(),
    })
}

pub(super) struct TravelRuntime {
    authority: TravelAuthorityConfig,
    store: crate::travel_recovery::TravelRecoveryStore,
    session: Option<crate::travel_recovery::TravelSession>,
    // Latched before the first activation side effect. An uncertain external
    // CAS or failed audit can never restore ordinary custody by leaving None.
    attempted: bool,
    original_scope: [u8; 32],
    audit_path: PathBuf,
}
impl TravelRuntime {
    pub(super) fn from_startup(
        startup: ValidatedTravelStartup,
        audit_path: Option<PathBuf>,
    ) -> EnclaveResult<Self> {
        if audit_path.as_ref() != Some(&startup.audit_path) {
            fail!(EACCES, "TRAVEL_AUDIT_PATH_MISMATCH");
        }
        Ok(Self {
            authority: startup.authority,
            store: startup.store,
            original_scope: startup.session.original_scope,
            session: Some(startup.session),
            attempted: true,
            audit_path: startup.audit_path,
        })
    }
    fn revalidate(&mut self) -> EnclaveResult<crate::travel_recovery::TravelSession> {
        let previous = self
            .session
            .clone()
            .ok_or_else(|| err!(EACCES, "TRAVEL_ACTIVATION_REQUIRED"))?;
        let authority = &self.authority;
        let mut source = || authority.read_roster();
        let mut current = self.store.current_service_session(
            self.original_scope,
            &mut source,
            &SystemClock::default(),
            &self.audit_path,
        )?;
        if current.token_sha256 != previous.token_sha256 {
            fail!(EACCES, "TRAVEL_SESSION_CHANGED");
        }
        current.valid_until_utc_ms = current.valid_until_utc_ms.min(previous.valid_until_utc_ms);
        current.deadline_ns = current.deadline_ns.min(previous.deadline_ns);
        if SystemClock::default().now_ns() >= current.deadline_ns {
            fail!(EACCES, "TRAVEL_TOKEN_EXPIRED");
        }
        self.session = Some(current.clone());
        Ok(current)
    }
}

impl State {
    pub(super) fn travel_active(&self) -> bool {
        self.travel
            .as_ref()
            .is_some_and(|travel| travel.session.is_some())
    }
    pub(super) fn require_no_travel(&self) -> EnclaveResult<()> {
        if self
            .travel
            .as_ref()
            .is_some_and(|travel| travel.attempted || travel.session.is_some())
        {
            fail!(EACCES, "TRAVEL_SENSITIVE_ACTION_FORBIDDEN");
        }
        Ok(())
    }
    pub(super) fn check_travel_request(&mut self, request: &VaultRequest) -> EnclaveResult<()> {
        if self.require_no_travel().is_ok() {
            return Ok(());
        }
        if matches!(
            request,
            VaultRequest::Tamper(_) | VaultRequest::Status | VaultRequest::BootEpoch
        ) {
            return Ok(());
        }
        if matches!(request, VaultRequest::ActivateTravelRecovery { .. }) && !self.travel_active() {
            return Ok(());
        }
        if !self.travel_active() {
            fail!(EACCES, "TRAVEL_ACTIVATION_REQUIRED");
        }
        if matches!(
            request,
            VaultRequest::Tokenize { bulk_set: true, .. }
                | VaultRequest::ScrubText { bulk_set: true, .. }
                | VaultRequest::Tokenize { grant: Some(_), .. }
                | VaultRequest::ScrubText { grant: Some(_), .. }
        ) {
            fail!(EACCES, "TRAVEL_A4_INGEST_FORBIDDEN");
        }
        if !matches!(
            request,
            VaultRequest::Tokenize { .. }
                | VaultRequest::ScrubText { .. }
                | VaultRequest::AllocateSlot
        ) {
            fail!(EACCES, "TRAVEL_SENSITIVE_ACTION_FORBIDDEN");
        }
        self.current_travel().map(|_| ())
    }
    pub(super) fn current_travel(
        &mut self,
    ) -> EnclaveResult<crate::travel_recovery::TravelSession> {
        let now = self.clock.now_unix();
        let transport_expiry = self.refresh_envelope_policy(now)?;
        let original = self
            .membership_checkpoint
            .as_ref()
            .ok_or_else(|| err!(EACCES, "TRAVEL_ORIGINAL_MEMBERSHIP_REQUIRED"))?
            .travel_scope()?;
        let runtime = self
            .travel
            .as_mut()
            .ok_or_else(|| err!(EACCES, "TRAVEL_INDEPENDENT_ANCHOR_REQUIRED"))?;
        if runtime.original_scope != original {
            fail!(EACCES, "TRAVEL_ORIGINAL_SCOPE");
        }
        let mut session = runtime.revalidate()?;
        if let Some(expiry) = self.release_valid_until(transport_expiry) {
            let expiry = u64::try_from(expiry)
                .ok()
                .and_then(|s| s.checked_mul(1000))
                .ok_or_else(|| err!(EACCES, "TRAVEL_TOKEN_EXPIRED"))?;
            Self::shorten_travel_expiry(&mut session, expiry)?;
        }
        session.deadline_ns = Self::travel_deadline(&session, self.envelope_deadline_ns)?;
        self.travel.as_mut().unwrap().session = Some(session.clone());
        Ok(session)
    }
    fn shorten_travel_expiry(
        session: &mut crate::travel_recovery::TravelSession,
        expiry: u64,
    ) -> EnclaveResult<()> {
        if expiry < session.valid_until_utc_ms {
            // Preserve the independent trusted-time mapping. Recomputing this
            // earlier signed cutoff from host wall time permits clock rollback.
            let reduction = session
                .valid_until_utc_ms
                .checked_sub(expiry)
                .and_then(|ms| ms.checked_mul(1_000_000))
                .ok_or_else(|| err!(EACCES, "TRAVEL_TOKEN_EXPIRED"))?;
            session.deadline_ns = session
                .deadline_ns
                .checked_sub(reduction)
                .ok_or_else(|| err!(EACCES, "TRAVEL_TOKEN_EXPIRED"))?;
            session.valid_until_utc_ms = expiry;
        }
        if SystemClock::default().now_ns() >= session.deadline_ns {
            fail!(EACCES, "TRAVEL_TOKEN_EXPIRED");
        }
        Ok(())
    }
    fn travel_deadline(
        session: &crate::travel_recovery::TravelSession,
        extra: Option<u64>,
    ) -> EnclaveResult<u64> {
        let wall_expiry = i64::try_from(session.valid_until_utc_ms / 1000)
            .map_err(|_| err!(EACCES, "TRAVEL_TOKEN_EXPIRED"))?;
        let deadline =
            VaultService::release_boot_deadline(Some(session.deadline_ns), Some(wall_expiry))?
                .unwrap();
        Ok(extra.map_or(deadline, |bound| bound.min(deadline)))
    }
}

impl VaultService {
    // Sensitive RPC responses without an existing stronger permit share the
    // activation fence, including DPoP/challenges and floor acknowledgments.
    pub(super) fn attach_non_travel_release(&self, captured: u64) -> EnclaveResult<()> {
        // Retain the SAME request-entry generation: a cancellation while the
        // operation ran must not supply a later generation to its old reply.
        let state = self.lock_sensitive_state()?;
        drop(state);
        let generation = self.cas_key_generation.clone();
        let state = self.state.clone();
        let permit = self.selected_release_permit(
            self.cas_key_release.clone(),
            Arc::new(move || {
                if captured == u64::MAX
                    || generation.load(std::sync::atomic::Ordering::SeqCst) != captured
                {
                    fail!(EACCES, "CUSTODY_AUTHORIZATION_REVOKED");
                }
                state
                    .try_lock()
                    .map_err(|_| err!(EAGAIN, "CUSTODY_RELEASE_BUSY"))?
                    .require_no_travel()
            }),
            selected_owner_dependency::SelectedOwnerReply::Authority,
        );
        enclave_core::ipc::attach_release_permit(permit);
        Ok(())
    }
    /// Install already independently provisioned travel trust and anchor. This
    /// is not an RPC and never enables a mode by itself. No installed provider
    /// is inferred from a file or from submitted token fields.
    pub fn configure_travel_recovery(
        &self,
        authority: TravelAuthorityConfig,
        anchor: Box<dyn TravelRecoveryAnchor>,
    ) -> EnclaveResult<()> {
        let mut state = self.lock_state()?;
        state.require_no_travel()?;
        if state.profile != Profile::L3 {
            fail!(EACCES, "TRAVEL_PERMANENT_L3_REQUIRED");
        }
        if state.travel.is_some() {
            fail!(EALREADY, "TRAVEL_AUTHORITY_ALREADY_CONFIGURED");
        }
        let now = state.clock.now_unix();
        state.refresh_envelope_policy(now)?;
        let scope = state
            .membership_checkpoint
            .as_ref()
            .ok_or_else(|| err!(EACCES, "TRAVEL_ORIGINAL_MEMBERSHIP_REQUIRED"))?
            .travel_scope()?;
        let audit_path = state
            .audit_path
            .clone()
            .ok_or_else(|| err!(EACCES, "TRAVEL_AUDIT_REQUIRED"))?;
        if state.journal.is_none() {
            fail!(EACCES, "TRAVEL_AUDIT_REQUIRED");
        }
        let directory = state
            .state_dir
            .as_deref()
            .ok_or_else(|| err!(EACCES, "ENROLLMENT_STATE_REQUIRED"))?;
        let store = crate::travel_recovery::TravelRecoveryStore::open_anchored(
            directory,
            authority.pins()?,
            scope,
            anchor,
        )?;
        let attempted = store.service_transition_attempted();
        state.travel = Some(TravelRuntime {
            authority,
            store,
            session: None,
            attempted,
            original_scope: scope,
            audit_path,
        });
        Ok(())
    }
    pub(super) fn preflight_travel_request(&self, request: &VaultRequest) -> EnclaveResult<()> {
        self.lock_state()?.check_travel_request(request)
    }
    pub(super) fn activate_travel_recovery(
        &self,
        peer: &PeerCredentials,
        token: &[u8],
        start: u64,
    ) -> EnclaveResult<VaultResponse> {
        let complete = start
            .checked_add(crate::ceremony::CEREMONY_BUDGET_NS)
            .ok_or_else(|| err!(ETIMEDOUT, "TRAVEL_DEADLINE"))?;
        self.cas_operator(peer)?;
        if token.is_empty() || token.len() > 128 * 1024 {
            fail!(E2BIG, "TRAVEL_INPUT_SIZE");
        }
        let mut ceremony = self.lock_ceremony()?;
        {
            let mut state = self.lock_state()?;
            if state.profile != Profile::L3 {
                fail!(EACCES, "TRAVEL_PERMANENT_L3_REQUIRED");
            }
            let runtime = state
                .travel
                .as_mut()
                .ok_or_else(|| err!(EACCES, "TRAVEL_INDEPENDENT_ANCHOR_REQUIRED"))?;
            if runtime.session.is_some() {
                fail!(EALREADY, "TRAVEL_ALREADY_ACTIVE");
            }
            runtime.attempted = true;
        }
        self.revoke_cas_keys()?;
        ceremony.setup_only = true;
        let generation = self
            .cas_key_generation
            .load(std::sync::atomic::Ordering::SeqCst);
        let mut state = self.lock_state()?;
        state.cas_key_leases.clear();
        state.cas_key_deadlines.clear();
        state.namespace_challenges.clear();
        if state.profile != Profile::L3 {
            fail!(EACCES, "TRAVEL_PERMANENT_L3_REQUIRED");
        }
        let now = state.clock.now_unix();
        let transport_expiry = state.refresh_envelope_policy(now)?;
        let scope = state
            .membership_checkpoint
            .as_ref()
            .ok_or_else(|| err!(EACCES, "TRAVEL_ORIGINAL_MEMBERSHIP_REQUIRED"))?
            .travel_scope()?;
        if state.journal.is_none() {
            fail!(EACCES, "TRAVEL_AUDIT_REQUIRED");
        }
        let mut runtime = state
            .travel
            .take()
            .ok_or_else(|| err!(EACCES, "TRAVEL_INDEPENDENT_ANCHOR_REQUIRED"))?;
        if runtime.session.is_some() {
            state.travel = Some(runtime);
            fail!(EALREADY, "TRAVEL_ALREADY_ACTIVE");
        }
        // Retain the configured owner even on any failure; a missing Option
        // must never turn an uncertain anchored journal into normal custody.
        let result = (|| {
            if runtime.original_scope != scope {
                fail!(EACCES, "TRAVEL_ORIGINAL_SCOPE");
            }
            let authority = &runtime.authority;
            let mut source = || authority.read_roster();
            let permit = runtime
                .store
                .burn(token, &mut source, &SystemClock::default())?;
            let mut candidate =
                runtime
                    .store
                    .finish(permit, &mut source, &SystemClock::default())?;
            candidate.shorten_operation_deadline(
                state.release_deadline(Some(complete)).unwrap_or(complete),
            );
            if let Some(expiry) = state.release_valid_until(transport_expiry) {
                candidate.shorten(
                    u64::try_from(expiry)
                        .ok()
                        .and_then(|s| s.checked_mul(1000))
                        .ok_or_else(|| err!(EACCES, "TRAVEL_TOKEN_EXPIRED"))?,
                )?;
            }
            let deadline = candidate.deadline_ns().min(complete);
            runtime
                .store
                .check_service_candidate_deadlines(&candidate, &SystemClock::default())?;
            let (epoch, sequence) = Self::begin_governed(&mut state)?;
            let simulated = state.simulated;
            let audit = state.journal.as_mut().unwrap().append_at(
                &epoch,
                sequence,
                candidate.activation_payload(scope, simulated),
            )?;
            let session = runtime.store.activate_service(
                candidate,
                scope,
                audit,
                simulated,
                &mut source,
                &SystemClock::default(),
            )?;
            if SystemClock::default().now_ns() >= deadline {
                fail!(ETIMEDOUT, "TRAVEL_DEADLINE");
            }
            if self
                .cas_key_generation
                .load(std::sync::atomic::Ordering::SeqCst)
                != generation
            {
                fail!(EACCES, "CUSTODY_AUTHORIZATION_REVOKED");
            }
            runtime.session = Some(session.clone());
            Ok((session, deadline))
        })();
        state.travel = Some(runtime);
        drop(state);
        // The existing cancellation/generation fence invalidates every old
        // critical grant before publishing effective public-only operation.
        let (session, deadline) = match result {
            Ok(value) => value,
            Err(error) => {
                drop(ceremony);
                self.revoke_cas_keys()?;
                return Err(error);
            }
        };
        ceremony.setup_only = true;
        ceremony.leases = crate::lease::LeaseTable::new();
        {
            let mut state = self.lock_state()?;
            state.cas_key_leases.clear();
            state.cas_key_deadlines.clear();
            state.namespace_challenges.clear();
            let mut lifecycle = CustodyLifecycle::boot(Profile::L2);
            lifecycle.on(CustodyEvent::PublicIngestInit)?;
            state.lifecycle = lifecycle;
        }
        drop(ceremony);
        self.attach_travel_release(generation, Some(deadline))?;
        Ok(VaultResponse::TravelRecoveryActive {
            token_sha256: session.token_sha256,
            valid_until_utc_ms: session.valid_until_utc_ms,
            effective_profile: Profile::L2,
        })
    }
    pub(super) fn attach_travel_release(
        &self,
        generation: u64,
        operation_deadline: Option<u64>,
    ) -> EnclaveResult<()> {
        let session = self.lock_state()?.current_travel()?;
        let deadline =
            operation_deadline.map_or(session.deadline_ns, |bound| bound.min(session.deadline_ns));
        let state = self.state.clone();
        let preflight_state = state.clone();
        let generations = self.cas_key_generation.clone();
        let token = session.token_sha256;
        let permit = self
            .selected_release_permit(
                self.cas_key_release.clone(),
                Arc::new(move || {
                    if generations.load(std::sync::atomic::Ordering::SeqCst) != generation
                        || generation == u64::MAX
                    {
                        fail!(EACCES, "CUSTODY_AUTHORIZATION_REVOKED");
                    }
                    if SystemClock::default().now_ns() >= deadline {
                        fail!(ETIMEDOUT, "TRAVEL_DEADLINE");
                    }
                    let state = state
                        .try_lock()
                        .map_err(|_| err!(EAGAIN, "CUSTODY_RELEASE_BUSY"))?;
                    let live = state
                        .travel
                        .as_ref()
                        .and_then(|travel| travel.session.as_ref())
                        .ok_or_else(|| err!(EACCES, "TRAVEL_ACTIVATION_REQUIRED"))?;
                    if live.token_sha256 != token
                        || SystemClock::default().now_ns() >= live.deadline_ns
                    {
                        fail!(EACCES, "TRAVEL_TOKEN_EXPIRED");
                    }
                    state.check_release_time(enclave_crypto::time::now_unix())
                }),
                selected_owner_dependency::SelectedOwnerReply::Authority,
            )
            .with_preflight(Arc::new(move || {
                preflight_state
                    .lock()
                    .map_err(|_| err!(EIO, "VAULT_STATE_POISONED"))?
                    .current_travel()
                    .map(|_| ())
            }));
        let remaining = deadline.saturating_sub(SystemClock::default().now_ns());
        enclave_core::ipc::attach_release_permit(permit.with_handoff_deadline(
            std::time::Instant::now() + std::time::Duration::from_nanos(remaining),
        ));
        Ok(())
    }
}

#[cfg(test)]
#[path = "non_travel_release_tests.rs"]
mod non_travel_release_tests;
