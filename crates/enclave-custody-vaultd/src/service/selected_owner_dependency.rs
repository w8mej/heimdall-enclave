//! Optional negative-only dependency of an explicitly selected native service.
//! A nonfailed latch is never evidence of a connected actor or readiness.
use super::*;
use enclave_core::power::selected_owner_session::SelectedOwnerSession;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    OnceLock,
};
use std::time::{Duration, Instant};

enum OriginalSession {
    Native(Arc<SelectedOwnerSession>),
    // A negative-only private test seam never satisfies native installation.
    #[cfg(test)]
    FixtureRevoked(Arc<AtomicBool>),
}
struct Original {
    instant: Instant,
    boot_end: u64,
    session: Option<OriginalSession>,
}
impl Original {
    fn admit(
        instant_before: Instant,
        boot_after: u64,
        instant: Instant,
        boot_end: u64,
    ) -> EnclaveResult<Self> {
        if boot_after == 0 || boot_after == u64::MAX || boot_end == 0 || boot_end == u64::MAX {
            fail!(EACCES, "SELECTED_OWNER_DEPENDENCY_INVALID_END");
        }
        let left = boot_end
            .checked_sub(boot_after)
            .filter(|left| *left > 0)
            .ok_or_else(|| err!(EACCES, "SELECTED_OWNER_DEPENDENCY_INVALID_END"))?;
        // Only raw-to-Instant shortening. Never derive/replace the admitted raw
        // endpoint, resample to renew an original, or extend an earlier cap.
        let converted = instant_before
            .checked_add(Duration::from_nanos(left))
            .ok_or_else(|| err!(EACCES, "SELECTED_OWNER_DEPENDENCY_INVALID_END"))?;
        let original = Self {
            instant: instant.min(converted),
            boot_end,
            session: None,
        };
        original.current(instant_before, boot_after)?;
        Ok(original)
    }
    fn current(&self, now: Instant, boot: u64) -> EnclaveResult<()> {
        if self.boot_end == 0
            || self.boot_end == u64::MAX
            || boot == 0
            || boot == u64::MAX
            || now >= self.instant
            || boot >= self.boot_end
        {
            fail!(EACCES, "SELECTED_OWNER_DEPENDENCY_FAILED");
        }
        Ok(())
    }
    fn require_not_revoked(&self) -> EnclaveResult<()> {
        match &self.session {
            Some(OriginalSession::Native(session)) => session.require_not_revoked(),
            #[cfg(test)]
            Some(OriginalSession::FixtureRevoked(revoked)) => {
                if revoked.load(Ordering::SeqCst) {
                    fail!(EACCES, "SELECTED_OWNER_DEPENDENCY_FAILED");
                }
                Ok(())
            }
            None => Ok(()),
        }
    }
}
struct FailureInner {
    failed: AtomicBool,
    original: OnceLock<Original>,
}

/// Shared terminal failure of the original selected-owner runtime. The actual
/// runtime must connect, retain and monitor its original channel separately.
#[derive(Clone)]
pub(crate) struct SelectedOwnerFailure(Arc<FailureInner>);
impl SelectedOwnerFailure {
    pub(crate) fn new() -> Self {
        Self(Arc::new(FailureInner {
            failed: AtomicBool::new(false),
            original: OnceLock::new(),
        }))
    }
    pub(crate) fn fail(&self) {
        self.0.failed.store(true, Ordering::SeqCst);
    }
    /// Bind once from the retained native session before threads/service
    /// installation. Invalid/duplicate attempts poison the original forever.
    pub(crate) fn bind_original(
        &self,
        session: Arc<SelectedOwnerSession>,
        instant: Instant,
        boot_end: u64,
    ) -> EnclaveResult<Instant> {
        let result = (|| {
            self.require_current()?;
            if self.0.original.get().is_some() {
                fail!(EACCES, "SELECTED_OWNER_DEPENDENCY_END_ALREADY_BOUND");
            }
            // Full original-record admission belongs only to startup, outside
            // the release serial. Later permits consume its atomic veto only.
            session.require_current()?;
            if boot_end != session.expires_boot_ns() {
                fail!(EACCES, "SELECTED_OWNER_DEPENDENCY_INVALID_END");
            }
            let instant = instant.min(session.original_instant_end());
            let end = self.bind_cap(instant, boot_end, Some(OriginalSession::Native(session)))?;
            self.require_original()?;
            Ok(end)
        })();
        if result.is_err() {
            self.fail();
        }
        result
    }
    #[cfg(test)]
    pub(crate) fn bind_fixture_original(
        &self,
        instant: Instant,
        boot_end: u64,
    ) -> EnclaveResult<Instant> {
        self.bind_cap(instant, boot_end, None)
    }
    fn bind_cap(
        &self,
        instant: Instant,
        boot_end: u64,
        session: Option<OriginalSession>,
    ) -> EnclaveResult<Instant> {
        let result = (|| {
            self.require_current()?;
            let before = Instant::now();
            let boot = enclave_core::clock::boot_clock_ns();
            let mut original = Original::admit(before, boot, instant, boot_end)?;
            original.session = session;
            let end = original.instant;
            self.0
                .original
                .set(original)
                .map_err(|_| err!(EACCES, "SELECTED_OWNER_DEPENDENCY_END_ALREADY_BOUND"))?;
            self.require_current()?;
            Ok(end)
        })();
        if result.is_err() {
            self.fail();
        }
        result
    }
    fn require_original(&self) -> EnclaveResult<()> {
        let result = (|| {
            self.require_current()?;
            if !self.0.original.get().is_some_and(|original| {
                matches!(&original.session, Some(OriginalSession::Native(_)))
            }) {
                fail!(EACCES, "SELECTED_OWNER_DEPENDENCY_END_REQUIRED");
            }
            self.require_current()
        })();
        if result.is_err() {
            self.fail();
        }
        result
    }
    pub(crate) fn require_current(&self) -> EnclaveResult<()> {
        if self.0.failed.load(Ordering::SeqCst) {
            fail!(EACCES, "SELECTED_OWNER_DEPENDENCY_FAILED");
        }
        if let Some(original) = self.0.original.get() {
            // Only immutable metadata and the existing local monotonic clocks
            // are read here, including while an actual final permit is serial.
            // No filesystem, boot-UUID sysctl, actor, State, callback or RPC.
            let current = (|| {
                original.require_not_revoked()?;
                original.current(Instant::now(), enclave_core::clock::boot_clock_ns())?;
                original.require_not_revoked()
            })();
            if let Err(error) = current {
                self.fail();
                return Err(error);
            }
        }
        if self.0.failed.load(Ordering::SeqCst) {
            fail!(EACCES, "SELECTED_OWNER_DEPENDENCY_FAILED");
        }
        Ok(())
    }
}

// Only status and cleanup acknowledgments are exempt. This private enum is
// derived from the actual request, never accepted from a caller or wire flag.
#[derive(Clone, Copy)]
pub(super) enum SelectedOwnerReply {
    Authority,
    Maintenance,
}
impl SelectedOwnerReply {
    pub(super) fn for_request(request: &VaultRequest) -> Self {
        if matches!(request, VaultRequest::Status | VaultRequest::Tamper(_)) {
            Self::Maintenance
        } else {
            Self::Authority
        }
    }
    fn require(self, slot: &OnceLock<SelectedOwnerFailure>) -> EnclaveResult<()> {
        if matches!(self, Self::Authority) {
            if let Some(failure) = slot.get() {
                failure.require_current()?;
            }
        }
        Ok(())
    }
}

fn native_selected_context() -> EnclaveResult<()> {
    use enclave_core::{
        codesign,
        deployment::{self, DeploymentRole, DeploymentSigningMode},
    };
    if !cfg!(target_os = "macos") || !codesign::enforced() {
        fail!(ENOSYS, "SELECTED_OWNER_DEPENDENCY_NATIVE_REQUIRED");
    }
    if enclave_core::ipc::geteuid() != DaemonId::CustodyVault.uid() {
        fail!(EPERM, "SELECTED_OWNER_DEPENDENCY_CUSTODY_REQUIRED");
    }
    let selected =
        deployment::selected().ok_or_else(|| err!(EACCES, "DEPLOYMENT_CONTEXT_REQUIRED"))?;
    if selected.target().role != DeploymentRole::DedicatedTest
        || selected.target().profile != Profile::L2
        || selected.target().signing_identity_mode != DeploymentSigningMode::LocalPins
        || codesign::signing_mode() != codesign::SigningMode::LocalPins
        || selected.target().broker.is_some()
        || !selected.target().shared_read_only_inputs.is_empty()
    {
        fail!(EACCES, "SELECTED_OWNER_DEPENDENCY_CONTEXT");
    }
    Ok(())
}

impl VaultService {
    /// Private software fixture for sibling runtime failure tests. This does
    /// not call or bypass a successful production native installation.
    #[cfg(test)]
    pub(crate) fn selected_owner_test_fixture(
        failure: SelectedOwnerFailure,
    ) -> EnclaveResult<Arc<Self>> {
        let service = Self::start(
            VaultConfig {
                profile: Profile::L2,
                ..Default::default()
            },
            VaultHardware::simulated(Profile::L2, enclave_crypto::time::now_unix())?,
        )?;
        service
            .selected_owner_failure
            .set(failure)
            .map_err(|_| err!(EACCES, "SELECTED_OWNER_TEST_FIXTURE_ALREADY_INSTALLED"))?;
        Ok(service)
    }

    /// Independently sampled read-only metadata, never an admission snapshot.
    #[cfg(test)]
    pub(crate) fn selected_owner_test_state(&self) -> (u64, bool, bool) {
        (
            self.cas_key_generation.load(Ordering::SeqCst),
            self.cas_keys_enabled.load(Ordering::SeqCst),
            self.ceremony_cancelled.load(Ordering::SeqCst),
        )
    }

    /// Bind the original runtime's latch once, before exposing the listener.
    /// This validates native scope and the retained singleton HID capability;
    /// it does not establish that the runtime's root connection is ready.
    pub(crate) fn install_selected_owner_failure(
        &self,
        failure: SelectedOwnerFailure,
    ) -> EnclaveResult<()> {
        native_selected_context()?;
        self.selected_owner_failure
            .set(failure)
            .map_err(|_| err!(EACCES, "SELECTED_OWNER_DEPENDENCY_ALREADY_INSTALLED"))?;
        let admitted = (|| {
            self.selected_owner_failure
                .get()
                .ok_or_else(|| err!(EACCES, "SELECTED_OWNER_DEPENDENCY_REQUIRED"))?
                .require_original()?;
            self.require_selected_owner()?;
            let ceremony = self.lock_ceremony()?;
            let state = self.lock_state()?;
            if state.profile != Profile::L2
                || state.simulated
                || state.travel_active()
                || state.membership_sterile
                || ceremony.hw.simulated
                || ceremony.hw.membership_devices.is_some()
            {
                fail!(
                    EACCES,
                    "SELECTED_OWNER_DEPENDENCY_NATIVE_SINGLETON_REQUIRED"
                );
            }
            ceremony
                .hw
                .yubikey
                .as_ref()
                .ok_or_else(|| err!(EACCES, "YUBIKEY_REQUIRED"))?
                .selected_transport_lifetime()?
                .require_current()?;
            self.require_selected_owner()
        })();
        if let Err(error) = admitted {
            // Guards from admission are gone before any fence or cleanup.
            // Keep the installed latch terminal even if cleanup also fails.
            self.fail_selected_owner()?;
            return Err(error);
        }
        Ok(())
    }

    /// Revoke before any State/preflight wait, then attempt ordinary cleanup.
    /// A blocked/failed cleanup cannot reopen the latch or old generation.
    pub(crate) fn fail_selected_owner(&self) -> EnclaveResult<()> {
        self.selected_owner_failure
            .get()
            .ok_or_else(|| err!(EACCES, "SELECTED_OWNER_DEPENDENCY_REQUIRED"))?
            .fail();
        let fence = self.revoke_cas_keys();
        // The release serial was dropped inside revoke_cas_keys. No callback,
        // State operation, actor join or global registry recursion runs in it.
        let cleanup = self.cleanup_tamper_after_fence(
            &PeerCredentials::local(enclave_core::ipc::geteuid(), 0),
            TamperEvent::UsbYank { docked: false },
        );
        fence?;
        cleanup.map(|_| ())
    }

    pub(super) fn require_selected_owner(&self) -> EnclaveResult<()> {
        SelectedOwnerReply::Authority.require(&self.selected_owner_failure)
    }

    // Preserve every original validator, serial, preflight and hard deadline.
    // Capturing the shared once-slot also covers a permit prepared before the
    // one permitted pre-listener installation. There is no replacement/reset.
    pub(super) fn selected_release_permit(
        &self,
        serial: Arc<Mutex<()>>,
        validate: Arc<dyn Fn() -> EnclaveResult<()> + Send + Sync>,
        boundary: SelectedOwnerReply,
    ) -> enclave_core::ipc::ReleasePermit {
        let failure = self.selected_owner_failure.clone();
        let original_ends = if matches!(boundary, SelectedOwnerReply::Authority) {
            failure
                .get()
                .and_then(|failure| failure.0.original.get())
                .map(|original| (original.instant, original.boot_end))
        } else {
            None
        };
        let permit = enclave_core::ipc::ReleasePermit::new(
            serial,
            Arc::new(move || {
                boundary.require(&failure)?;
                validate()?;
                boundary.require(&failure)
            }),
        );
        // Keep BOTH original clock domains during a started bounded handoff;
        // suspend or a raw-clock fault must not leave only converted Instant.
        // Both builders preserve min(existing,new) when original validators
        // append their action deadlines after this factory. No callback or
        // full record check is introduced in the serialized write path.
        if let Some((instant, boot_end)) = original_ends {
            permit
                .with_handoff_deadline(instant)
                .with_handoff_boot_deadline(boot_end)
        } else {
            permit
        }
    }

    // Selected L2 ingress can precede active asset enrollment and therefore
    // have no stronger permit. Add only this negative dependency/generation
    // fence, retaining all existing optional original time bounds.
    pub(super) fn attach_selected_dependency_release(
        &self,
        captured: u64,
        deadline: Option<u64>,
        valid_until: Option<i64>,
    ) -> EnclaveResult<()> {
        self.require_selected_owner()?;
        let generation = self.cas_key_generation.clone();
        let permit = self.selected_release_permit(
            self.cas_key_release.clone(),
            Arc::new(move || {
                if captured == u64::MAX || generation.load(Ordering::SeqCst) != captured {
                    fail!(EACCES, "CUSTODY_AUTHORIZATION_REVOKED");
                }
                if deadline.is_some_and(|end| SystemClock::default().now_ns() >= end) {
                    fail!(ETIMEDOUT, "CEREMONY_BUDGET_EXCEEDED");
                }
                Self::check_authority_deadline(valid_until, enclave_crypto::time::now_unix())
            }),
            SelectedOwnerReply::Authority,
        );
        let permit = if let Some(end) = Self::release_boot_deadline(deadline, valid_until)? {
            permit.with_handoff_deadline(
                std::time::Instant::now()
                    + std::time::Duration::from_nanos(
                        end.saturating_sub(SystemClock::default().now_ns()),
                    ),
            )
        } else {
            permit
        };
        enclave_core::ipc::attach_release_permit(permit);
        Ok(())
    }
}

#[cfg(test)]
#[path = "selected_owner_dependency_tests.rs"]
mod tests;
