//! Exact namespace capsule consumption and explicit original-primary migration.
//! Capsules hold encrypted existing KEKs, never membership or release grants.
use super::*;
use enclave_crypto::hpke_envelope::VerifiedEnvelopeContext;

impl State {
    pub(super) fn namespace_context(&mut self, now: i64) -> EnclaveResult<VerifiedEnvelopeContext> {
        self.require_no_travel()?;
        self.refresh_envelope_policy(now)?;
        let authority = self
            .envelope_authority
            .as_ref()
            .ok_or_else(|| err!(EACCES, "ENVELOPE_POLICY_AUTHORITY_REQUIRED"))?;
        let context = self
            .envelope_policy_source
            .as_ref()
            .ok_or_else(|| err!(EACCES, "ENVELOPE_POLICY_SOURCE_REQUIRED"))?
            .envelope_context(authority, self.profile, now)?;
        if Some(context.digest()) != self.envelope_policy_digest {
            fail!(ESTALE, "ENVELOPE_POLICY_CHANGED_MIGRATION_REQUIRED");
        }
        self.vault.refresh_authorized_context(&context, now)?;
        self.envelope_deadline_ns = context.deadline_ns();
        Ok(context)
    }
}

impl VaultService {
    pub(super) fn cas_key_custody_for(
        &self,
        peer: &PeerCredentials,
        wrapped: &enclave_crypto::namespace::WrappedNamespaceKey,
        operation: NamespaceCustodyOperation,
    ) -> EnclaveResult<(
        SecretKey32,
        enclave_crypto::namespace::CasKeyLease,
        Option<u64>,
    )> {
        let request_start = SystemClock::default().now_ns();
        self.cas_key_custody_for_started(peer, wrapped, operation, request_start)
    }
    pub(super) fn cas_key_custody_for_started(
        &self,
        peer: &PeerCredentials,
        wrapped: &enclave_crypto::namespace::WrappedNamespaceKey,
        operation: NamespaceCustodyOperation,
        request_start: u64,
    ) -> EnclaveResult<(
        SecretKey32,
        enclave_crypto::namespace::CasKeyLease,
        Option<u64>,
    )> {
        let complete_cap = request_start
            .checked_add(crate::ceremony::CEREMONY_BUDGET_NS)
            .ok_or_else(|| err!(ETIMEDOUT, "CEREMONY_BUDGET_EXCEEDED"))?;
        wrapped.validate()?;
        let captured_generation = self
            .cas_key_generation
            .load(std::sync::atomic::Ordering::SeqCst);
        let mut ceremony = self.lock_sensitive_ceremony()?;
        if ceremony.hw.simulated && !self.cas_keys_authorized() {
            fail!(EACCES, "CAS_KEY_LEASE_REVOKED");
        }
        ceremony.enter_generation(captured_generation);
        self.prepare_fresh_authorization(captured_generation)?;
        let (profile, mut lease, intent, mut lease_deadline, committed, capsule) = {
            let mut st = self.lock_sensitive_state()?;
            Self::namespace_peer(&st, peer)?;
            let now = st.clock.now_unix();
            let transport_expiry = st.refresh_envelope_policy(now)?;
            let committed = st.membership_checkpoint.is_some();
            let capsule = if matches!(
                operation,
                NamespaceCustodyOperation::Unwrap | NamespaceCustodyOperation::RotateFrom { .. }
            ) {
                match st.cas_keyring.capsule_access(wrapped)? {
                    crate::cas_keyring::NamespaceCapsuleAccess::Required(capsule) => {
                        Some(capsule.clone())
                    }
                    crate::cas_keyring::NamespaceCapsuleAccess::LegacyDirect if committed => {
                        fail!(EACCES, "NAMESPACE_BACKUP_MIGRATION_REQUIRED")
                    }
                    crate::cas_keyring::NamespaceCapsuleAccess::LegacyDirect => None,
                }
            } else {
                None
            };
            let policy = st.envelope_policy_digest.unwrap_or([0; 32]);
            if !st.simulated && st.envelope_policy_digest.is_none() {
                fail!(EACCES, "ENVELOPE_POLICY_REQUIRED");
            }
            let (epoch, sequence) = Self::begin_governed(&mut st)?;
            let intent = namespace_intent(
                wrapped,
                &operation,
                st.profile,
                peer.uid,
                policy,
                &epoch,
                sequence,
                st.clock.now_unix(),
            )?;
            let expires = st
                .release_valid_until(transport_expiry)
                .map_or(now.saturating_add(60), |expiry| {
                    expiry.min(now.saturating_add(60))
                });
            let deadline = st.envelope_deadline_ns.unwrap_or(u64::MAX).min(
                SystemClock::default()
                    .now_ns()
                    .saturating_add(60_000_000_000),
            );
            (
                st.profile,
                enclave_crypto::namespace::CasKeyLease {
                    enterprise: None,
                    id: hex::encode(enclave_core::rng::bytes32()),
                    namespace: wrapped.namespace.clone(),
                    key_epoch: wrapped.epoch,
                    boot_epoch: epoch,
                    generation: captured_generation,
                    expires_unix: expires,
                },
                intent,
                deadline,
                committed,
                capsule,
            )
        };
        let before = ceremony.counters.clone();
        // Legacy software namespace fixtures explicitly model only dual shares.
        // Native releases always require the full D2 intent ceremony. Missing
        // independent A4 authority refuses before any physical key operation.
        let full_ceremony = !ceremony.hw.simulated || committed || capsule.is_some();
        let deadline_ns = full_ceremony.then_some(complete_cap);
        if full_ceremony {
            lease_deadline = lease_deadline.min(complete_cap);
            if SystemClock::default().now_ns() >= complete_cap {
                fail!(ETIMEDOUT, "CEREMONY_BUDGET_EXCEEDED");
            }
        }
        let prf = if !full_ceremony {
            let c = &mut *ceremony;
            Self::enrollment_prf(
                &mut c.hw,
                profile,
                PrfTier::A4,
                &mut c.counters,
                &mut c.counter_store,
            )
            .map(|prf| (prf, None, None))
        } else {
            if operation.action() == ActionClass::A4 && ceremony.hw.oidc_provider.is_none() {
                fail!(EACCES, "NAMESPACE_A4_AUTHORITY_REQUIRED");
            }
            ceremony
                .run_started(
                    &intent,
                    Some(PrfTier::A4),
                    Some(&self.ceremony_cancelled),
                    request_start,
                )
                .and_then(|mut grant| {
                    grant.check_valid_at(enclave_crypto::time::now_unix())?;
                    grant.check_valid_at_boot(SystemClock::default().now_ns())?;
                    grant.consume()?;
                    grant
                        .prf
                        .take()
                        .map(|prf| (prf, grant.valid_until_unix, grant.valid_until_boot_ns))
                        .ok_or_else(|| err!(EACCES, "PRF_MISSING"))
                })
        };
        ceremony.persist_counters(&before)?;
        let (prf, valid_until, valid_until_boot) = prf?;
        if let Some(expiry) = valid_until {
            lease.expires_unix = lease.expires_unix.min(expiry);
        }
        if let Some(deadline) = valid_until_boot {
            lease_deadline = lease_deadline.min(deadline);
        }
        let sep = ceremony.hw.sep.ecdh_share(PrfTier::A4)?;
        let revision = ceremony
            .hw
            .metadata_source
            .as_ref()
            .and_then(|source| source.revision());
        ceremony.hw.revalidate_metadata(
            revision,
            profile,
            operation.action(),
            enclave_crypto::time::now_unix(),
        )?;
        if let Some(deadline) = ceremony
            .hw
            .metadata_source
            .as_ref()
            .and_then(|source| source.deadline_ns())
        {
            lease_deadline = lease_deadline.min(deadline);
        }
        let selected_prf = prf
            .expose()
            .get(..32)
            .ok_or_else(|| err!(EACCES, "PRF_MISSING"))?;
        let kek = if let Some(capsule) = capsule {
            let mut st = self.lock_sensitive_state()?;
            let now = st.clock.now_unix();
            let context = st.namespace_context(now)?;
            let crate::cas_keyring::NamespaceCapsuleAccess::Required(current)=st.cas_keyring.capsule_access(wrapped)? else {fail!(EACCES,"NAMESPACE_BACKUP_MIGRATION_REQUIRED");};
            if current != &capsule {
                fail!(ESTALE, "NAMESPACE_CAPSULE_CHANGED");
            }
            lease.expires_unix = lease.expires_unix.min(context.expires_unix());
            if let Some(deadline) = context.deadline_ns() {
                lease_deadline = lease_deadline.min(deadline);
            }
            st.vault.open_namespace_kek(
                &capsule,
                wrapped,
                &KekShares {
                    sep_ecdh_share: sep.expose(),
                    yubikey_prf: selected_prf,
                },
                &context,
                now,
            )?
        } else {
            enclave_crypto::namespace::custody_kek(
                sep.expose(),
                selected_prf,
                &wrapped.namespace,
                wrapped.wrapping_epoch,
            )?
        };
        if deadline_ns.is_some_and(|deadline| ceremony.clock.now_ns() >= deadline) {
            fail!(ETIMEDOUT, "CEREMONY_BUDGET_EXCEEDED");
        }
        self.finish_fresh_authorization(captured_generation, profile, operation.action())?;
        drop(ceremony);
        {
            let mut st = self.lock_sensitive_state()?;
            Self::namespace_peer(&st, peer)?;
            let now = st.clock.now_unix();
            if let Some(expiry) = st.refresh_envelope_policy(now)? {
                lease.expires_unix = lease.expires_unix.min(expiry);
            }
            if let Some(deadline) = st.envelope_deadline_ns {
                lease_deadline = lease_deadline.min(deadline);
            }
            lease_deadline =
                Self::release_boot_deadline(Some(lease_deadline), Some(lease.expires_unix))?
                    .ok_or_else(|| err!(EACCES, "CAS_KEY_LEASE_REVOKED"))?;
            if !self.cas_keys_authorized()
                || self
                    .cas_key_generation
                    .load(std::sync::atomic::Ordering::SeqCst)
                    != lease.generation
                || lease.expires_unix <= now
            {
                fail!(EACCES, "CAS_KEY_LEASE_REVOKED");
            }
            if profile == Profile::L3
                && st.lifecycle.state() == crate::lifecycle::CustodyState::SterileLocked
            {
                st.lifecycle.on(CustodyEvent::DualCustodyUnlock)?;
            }
            st.cas_key_leases.retain(|_, v| v.expires_unix > now);
            let valid_ids = st
                .cas_key_leases
                .keys()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>();
            st.cas_key_deadlines.retain(|id, _| valid_ids.contains(id));
            if st.cas_key_leases.len() >= 128 {
                fail!(EAGAIN, "CAS_KEY_LEASE_LIMIT");
            }
            st.cas_key_deadlines
                .insert(lease.id.clone(), lease_deadline);
            st.cas_key_leases.insert(lease.id.clone(), lease.clone());
        }
        self.check_cas_lease(peer, &lease)?;
        let deadline_ns =
            Some(deadline_ns.map_or(lease_deadline, |deadline| deadline.min(lease_deadline)));
        self.attach_lifecycle_release(
            captured_generation,
            deadline_ns,
            Some(lease.expires_unix),
            self.lock_sensitive_state()?.active_asset_guard.clone(),
        )?;
        Ok((kek, lease, deadline_ns))
    }

    /// Migrate one complete registered namespace, with actual ORIGINAL primary
    /// shares and one fresh full A4 grant. Neither backup access nor a partial
    /// candidate can replace the canonical DEKs, envelopes or retirement floor.
    pub(super) fn migrate_namespace_backup(
        &self,
        peer: &PeerCredentials,
        namespace: &str,
    ) -> EnclaveResult<VaultResponse> {
        let start = SystemClock::default().now_ns();
        let cap = start
            .checked_add(crate::ceremony::CEREMONY_BUDGET_NS)
            .ok_or_else(|| err!(ETIMEDOUT, "CEREMONY_BUDGET_EXCEEDED"))?;
        self.cas_operator(peer)?;
        let generation = self
            .cas_key_generation
            .load(std::sync::atomic::Ordering::SeqCst);
        let mut ceremony = self.lock_sensitive_ceremony()?;
        ceremony.enter_generation(generation);
        self.prepare_fresh_authorization(generation)?;
        let (expected, profile, intent, mut deadline, mut valid_until) = {
            let mut state = self.lock_sensitive_state()?;
            let now = state.clock.now_unix();
            let guard = state
                .active_asset_guard
                .as_ref()
                .ok_or_else(|| err!(EACCES, "ASSET_MEMBERSHIP_COMMITTED_REQUIRED"))?;
            if state.membership_checkpoint.is_none()
                || guard.member_index() != Some(0)
                || ceremony
                    .hw
                    .active_asset_guard
                    .as_ref()
                    .and_then(|guard| guard.member_index())
                    != Some(0)
            {
                fail!(EACCES, "NAMESPACE_CAPSULE_PRIMARY_REQUIRED");
            }
            let context = state.namespace_context(now)?;
            let expected = state.cas_keyring.namespace_snapshot(namespace)?;
            let first = expected
                .first()
                .ok_or_else(|| err!(EACCES, "CAS_KEY_NOT_REGISTERED"))?;
            if matches!(
                state.cas_keyring.capsule_access(first)?,
                crate::cas_keyring::NamespaceCapsuleAccess::Required(_)
            ) {
                fail!(EALREADY, "NAMESPACE_BACKUP_ALREADY_MIGRATED");
            }
            let digests = expected
                .iter()
                .map(Self::envelope_digest)
                .collect::<EnclaveResult<Vec<_>>>()?;
            let (epoch, sequence) = Self::begin_governed(&mut state)?;
            let intent = namespace_intent(
                first,
                &NamespaceCustodyOperation::MigratePrimary {
                    canonical_envelope_blake3: digests,
                },
                state.profile,
                peer.uid,
                context.digest(),
                &epoch,
                sequence,
                now,
            )?;
            let deadline = state.release_deadline(Some(cap)).unwrap_or(cap);
            let valid_until = state
                .release_valid_until(Some(context.expires_unix()))
                .ok_or_else(|| err!(EACCES, "CUSTODY_AUTHORITY_EXPIRED"))?;
            (expected, state.profile, intent, deadline, valid_until)
        };
        if ceremony.hw.oidc_provider.is_none() {
            fail!(EACCES, "NAMESPACE_A4_AUTHORITY_REQUIRED");
        }
        self.check_namespace_window(generation, deadline, valid_until)?;
        let before = ceremony.counters.clone();
        let result = ceremony.run_started(
            &intent,
            Some(PrfTier::A4),
            Some(&self.ceremony_cancelled),
            start,
        );
        ceremony.persist_counters(&before)?;
        let mut grant = result?;
        grant.check_valid_at(enclave_crypto::time::now_unix())?;
        grant.check_valid_at_boot(SystemClock::default().now_ns())?;
        grant.consume()?;
        if let Some(bound) = grant.valid_until_unix {
            valid_until = valid_until.min(bound);
        }
        if let Some(bound) = grant.valid_until_boot_ns {
            deadline = deadline.min(bound);
        }
        let prf = grant
            .prf
            .take()
            .ok_or_else(|| err!(EACCES, "PRF_MISSING"))?;
        let prf = prf
            .expose()
            .get(..32)
            .ok_or_else(|| err!(EACCES, "PRF_MISSING"))?;
        let sep = ceremony.hw.sep.ecdh_share(PrfTier::A4)?;
        let revision = ceremony
            .hw
            .metadata_source
            .as_ref()
            .and_then(|source| source.revision());
        ceremony.hw.revalidate_metadata(
            revision,
            profile,
            ActionClass::A4,
            enclave_crypto::time::now_unix(),
        )?;
        if let Some(bound) = ceremony
            .hw
            .metadata_source
            .as_ref()
            .and_then(|source| source.deadline_ns())
        {
            deadline = deadline.min(bound);
        }
        self.check_namespace_window(generation, deadline, valid_until)?;
        let mut state = self.lock_sensitive_state()?;
        let now = state.clock.now_unix();
        let context = state.namespace_context(now)?;
        if state
            .active_asset_guard
            .as_ref()
            .and_then(|guard| guard.member_index())
            != Some(0)
            || state.cas_keyring.namespace_snapshot(namespace)? != expected
        {
            fail!(ESTALE, "NAMESPACE_MIGRATION_SOURCE_CHANGED");
        }
        valid_until = valid_until.min(context.expires_unix());
        if let Some(bound) = context.deadline_ns() {
            deadline = deadline.min(bound);
        }
        let capsules = state.vault.stage_namespace_primary_migration(
            &expected,
            &KekShares {
                sep_ecdh_share: sep.expose(),
                yubikey_prf: prf,
            },
            &context,
            now,
            || self.check_namespace_window(generation, deadline, valid_until),
        )?;
        for (canonical, capsule) in expected.iter().zip(&capsules) {
            state.vault.validate_namespace_kek_capsule(
                capsule,
                canonical,
                &context,
                state.clock.now_unix(),
            )?;
        }
        self.check_namespace_window(generation, deadline, valid_until)?;
        let result = state
            .cas_keyring
            .migrate_namespace(namespace, &expected, capsules);
        let mut state = self.finish_cas_keyring_write(state, result)?;
        // A successful save is durable migration, never a reusable live grant.
        // Later cancellation/expiry returns no acknowledgement and never rolls
        // back the new mode, current pointer or any consumed counter/floor.
        self.check_namespace_window(generation, deadline, valid_until)?;
        let now = state.clock.now_unix();
        let refreshed = state.namespace_context(now)?;
        valid_until = valid_until.min(refreshed.expires_unix());
        if let Some(bound) = refreshed.deadline_ns() {
            deadline = deadline.min(bound);
        }
        let guard = state
            .active_asset_guard
            .clone()
            .ok_or_else(|| err!(EACCES, "ASSET_ACTIVE_REQUIRED"))?;
        self.check_namespace_window(generation, deadline, valid_until)?;
        drop(state);
        self.finish_fresh_authorization(generation, profile, ActionClass::A4)?;
        // All IO is complete before this bounded serial section. Established
        // pre-fence releases stand; later old namespace leases cannot be used.
        let _release = self
            .cas_key_release
            .try_lock()
            .map_err(|error| match error {
                std::sync::TryLockError::WouldBlock => err!(EAGAIN, "CUSTODY_RELEASE_BUSY"),
                std::sync::TryLockError::Poisoned(_) => err!(EIO, "CAS_RELEASE_LOCK"),
            })?;
        self.check_namespace_window(generation, deadline, valid_until)?;
        guard.check_release(enclave_crypto::time::now_unix())?;
        let mut state = self.state.try_lock().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => err!(EAGAIN, "CUSTODY_RELEASE_BUSY"),
            std::sync::TryLockError::Poisoned(_) => err!(EIO, "VAULT_STATE_POISONED"),
        })?;
        state.check_release_time(enclave_crypto::time::now_unix())?;
        state
            .cas_key_leases
            .retain(|_, lease| lease.namespace != namespace);
        let ids = state
            .cas_key_leases
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        state.cas_key_deadlines.retain(|id, _| ids.contains(id));
        drop(state);
        drop(_release);
        drop(ceremony);
        self.attach_lifecycle_release(generation, Some(deadline), Some(valid_until), Some(guard))?;
        Ok(VaultResponse::NamespaceBackupMigrated {
            namespace: namespace.into(),
            envelopes: expected.len(),
        })
    }

    fn check_namespace_window(
        &self,
        generation: u64,
        deadline: u64,
        valid_until: i64,
    ) -> EnclaveResult<()> {
        if self
            .ceremony_cancelled
            .load(std::sync::atomic::Ordering::SeqCst)
            || self
                .cas_key_generation
                .load(std::sync::atomic::Ordering::SeqCst)
                != generation
        {
            fail!(EACCES, "CUSTODY_AUTHORIZATION_REVOKED");
        }
        if SystemClock::default().now_ns() >= deadline {
            fail!(ETIMEDOUT, "CEREMONY_BUDGET_EXCEEDED");
        }
        Self::check_authority_deadline(Some(valid_until), enclave_crypto::time::now_unix())
    }
}
