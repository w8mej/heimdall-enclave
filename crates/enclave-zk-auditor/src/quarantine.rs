//! ADR-012 graduated `HardwareIntegrityQuarantine`.
//!
//! * Page-zero faults (`fault_addr < 0x10000`) never latch: kill, zeroize,
//!   telemetry, `launchd` restart after `ThrottleInterval = 30 s`; they latch
//!   only if `>= 5` occur within `10 min`.
//! * Heap-tag / `PAC` / redzone (cookie) faults increment a sealed strike
//!   counter ([`SealedStore`]; NVRAM `enclave-hiq` under a SEP key on
//!   hardware). **Missing state on an initialised host, an invalid MAC or a
//!   rolled-back generation ⇒ latched**:
//!   `L1`/`L2` latch on Strike 2 within 24 h (Strike 1 kills, zeroizes,
//!   rotates tag seeds and delays respawn 300 s). `L3` latches on Strike 1
//!   for heap-tag / `PAC` only; redzone / cookie and non-null `SEGV` use
//!   Strike 2. All integrity kinds share the same rolling 24 h history.
//! * Recovery: a per-host `k`-of-`n` Ed25519 `UnquarantineGrant`, or a
//!   TUF-signed fleet grant bound to the fixed binary's `cdhash`.

use std::path::{Path, PathBuf};

use enclave_core::error::EnclaveResult;
use enclave_core::nvram::{load_hiq, save_hiq, PersistedHiq};
use enclave_core::profile::Profile;
pub use enclave_core::quarantine_types::{
    FaultKind, FaultReport, Response, NULL_BURST_COUNT, NULL_BURST_WINDOW_MS, NULL_PAGE_LIMIT,
    STRIKE_WINDOW_MS,
};
use enclave_core::sealed::{Loaded, SealedStore};
use enclave_core::secret::SecretKey32;
use enclave_core::{err, fail};
use enclave_crypto::multisig::{QuorumPolicy, QuorumSignature};
use enclave_crypto::tuf::TufClient;
use serde::{Deserialize, Serialize};

/// Sealed-store name (`<dir>/quarantine.{sealed,gen}`).
pub const STORE: &str = "quarantine";

/// The quarantine state machine.
#[derive(Debug)]
pub struct Quarantine {
    profile: Profile,
    dir: PathBuf,
    key: SecretKey32,
    store: Option<SealedStore>,
    st: PersistedHiq,
    integrity: Option<String>,
    // An ambiguous save must not be retried through this live owner. Reopen
    // authenticates both stores before any further state publication.
    persistence_failed: bool,
}

impl Quarantine {
    /// Open the sealed quarantine state in `dir` (GAP-12) under the daemon's
    /// sealing key ([`enclave_core::sealed::sealing_key`]; on hardware the
    /// SEP-unwrapped key and the `enclave-hiq` NVRAM checkpoint).
    ///
    /// Only a never-initialised directory starts clean. Missing state on an
    /// initialised host (sealing key or legacy strike file present), a bad
    /// MAC, a rolled-back generation or an unparsable body is **latched**.
    pub fn open(profile: Profile, dir: &Path) -> EnclaveResult<Self> {
        enclave_core::fsutil::private_dir(dir)?;
        let host_enrolled = !cfg!(test)
            && ((dir.starts_with("/var/run/enclave")
                || dir.starts_with("/opt/enterprise")
                || dir.starts_with("/Library/Application Support/EnterpriseEnclave"))
                && (std::path::Path::new("/Library/Application Support/EnterpriseEnclave")
                    .exists()
                    || std::path::Path::new("/opt/enterprise/enclave").exists()));
        let initialised = dir.join("sealing.key").exists() || host_enrolled;
        let legacy = if initialised {
            None
        } else {
            Self::legacy_state(dir)
        };
        let key = enclave_core::sealed::sealing_key(dir, STORE)?;
        let mut q = Self::open_with(profile, dir, key, initialised)?;
        if let Some(p) = legacy {
            // First boot of the sealed format on a host that kept the
            // pre-GAP-12 file: carry its strikes and latch over (an
            // unverifiable legacy file is latched), then retire it.
            if p.is_none() {
                q.integrity = Some("STATE_TAMPERED: legacy strike file failed its MAC".to_owned());
            }
            q.st = p.unwrap_or_else(PersistedHiq::latched);
            q.persist()?;
            for f in ["zk-strikes.json", "zk-strikes.key"] {
                let _ = std::fs::remove_file(dir.join(f));
            }
        }
        Ok(q)
    }

    /// Pre-GAP-12 `zk-strikes.json` + plaintext `zk-strikes.key`: `None` when
    /// absent, `Some(None)` when present but unverifiable.
    fn legacy_state(dir: &Path) -> Option<Option<PersistedHiq>> {
        #[derive(Deserialize)]
        struct Legacy {
            state: String,
            mac: String,
        }
        let b = std::fs::read(dir.join("zk-strikes.json")).ok()?;
        let key = std::fs::read(dir.join("zk-strikes.key"))
            .ok()
            .and_then(|k| <[u8; 32]>::try_from(k.as_slice()).ok())
            .map(SecretKey32::new);
        let verified = serde_json::from_slice::<Legacy>(&b)
            .ok()
            .zip(key)
            .and_then(|(l, k)| {
                enclave_core::secret::ct_eq(
                    hex::encode(k.mac(l.state.as_bytes())).as_bytes(),
                    l.mac.as_bytes(),
                )
                .then_some(l.state)
            });
        Some(verified.and_then(|s| serde_json::from_str(&s).ok()))
    }

    /// As [`Self::open`] with an explicit key; `initialised` says whether this
    /// host has ever held quarantine state.
    pub fn open_with(
        profile: Profile,
        dir: &Path,
        key: SecretKey32,
        initialised: bool,
    ) -> EnclaveResult<Self> {
        let (store, mut st, mut integrity) = match SealedStore::open_with(dir, STORE, key.clone()) {
            Ok((s, Loaded::State(b))) => match enclave_core::sealed::decode::<PersistedHiq>(&b) {
                Ok(p) => (Some(s), p, None),
                Err(e) => (Some(s), PersistedHiq::latched(), Some(e.to_string())),
            },
            Ok((s, Loaded::Fresh)) if initialised => (
                Some(s),
                PersistedHiq::latched(),
                Some("STATE_MISSING: quarantine state absent on an initialised host".to_owned()),
            ),
            Ok((s, Loaded::Fresh)) => (Some(s), PersistedHiq::default(), None),
            // Unreadable, tampered or rolled back: latched, and nothing is
            // written over the evidence until an UnquarantineGrant.
            Err(e) => (None, PersistedHiq::latched(), Some(e.to_string())),
        };

        // NVRAM enclave-hiq integration (GAP-12)
        let (nvram_st, nvram_err) = load_hiq(false, dir, &key, initialised)?;
        if let Some(err) = nvram_err {
            integrity = Some(err);
            st.latched = true;
        } else {
            if nvram_st.generation != st.generation {
                integrity.get_or_insert_with(|| {
                    "STATE_GENERATION_MISMATCH: sealed and NVRAM recovery floors differ".into()
                });
                st.latched = true;
            }
            // Only authenticated NVRAM state supplies a consumed-grant floor.
            // Never overwrite its newer generation with an older local copy.
            st.generation = st.generation.max(nvram_st.generation);
            st.latched |= nvram_st.latched;
        }
        if nvram_st.strikes.len() > st.strikes.len() {
            st.strikes = nvram_st.strikes;
        }
        if nvram_st.null_faults.len() > st.null_faults.len() {
            st.null_faults = nvram_st.null_faults;
        }

        let mut q = Self {
            profile,
            dir: dir.to_owned(),
            key,
            store,
            st,
            integrity,
            persistence_failed: false,
        };
        q.persist()?;
        Ok(q)
    }

    fn persist(&mut self) -> EnclaveResult<()> {
        self.persist_state(&self.st.clone())
    }

    fn persistence_ready(&self) -> EnclaveResult<()> {
        if self.persistence_failed {
            fail!(EIO, "QUARANTINE_REOPEN_REQUIRED");
        }
        Ok(())
    }

    fn persist_state(&mut self, next: &PersistedHiq) -> EnclaveResult<()> {
        self.persistence_ready()?;
        let result: EnclaveResult<()> = (|| {
            if let Some(s) = self.store.as_mut() {
                s.save_json(next)?;
            }
            save_hiq(false, &self.dir, &self.key, next)?;
            // save_hiq's local fallback currently suppresses write errors.
            // Authenticate the exact selected persistence endpoint, including
            // its complete generation/latch/history, before accepting success.
            let (saved, integrity) = load_hiq(false, &self.dir, &self.key, true)?;
            if integrity.is_some() || saved != *next {
                fail!(EIO, "QUARANTINE_PERSIST_READBACK");
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.st.latched = true;
            self.persistence_failed = true;
            self.integrity = Some(format!("QUARANTINE_PERSIST_UNCERTAIN: {error}"));
            return Err(error);
        }
        Ok(())
    }

    /// Re-initialise the store after a verified grant (the old one may be
    /// unreadable), then save the clean state.
    fn reset(&mut self) -> EnclaveResult<()> {
        self.persistence_ready()?;
        let next_gen = self.st.generation.checked_add(1)
            .ok_or_else(|| err!(E2BIG, "QUARANTINE_GENERATION_EXHAUSTED"))?;
        let next = PersistedHiq {
            generation: next_gen,
            ..Default::default()
        };
        let result: EnclaveResult<()> = (|| {
            if self.store.is_none() {
                for ext in ["sealed", "gen"] {
                    match std::fs::remove_file(self.dir.join(format!("{STORE}.{ext}"))) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(err!(EIO, "QUARANTINE_RESET", "{e}")),
                    }
                }
                self.store = Some(SealedStore::open_with(&self.dir, STORE, self.key.clone())?.0);
            }
            self.persist_state(&next)
        })();
        if let Err(error) = result {
            // A partial publication may already contain the new generation.
            // Retain every consumed floor and original strike history, latch
            // live work, and forbid blind retries until authenticated reopen.
            self.st.generation = next_gen;
            self.st.latched = true;
            self.persistence_failed = true;
            self.integrity = Some(format!("QUARANTINE_RESET_UNCERTAIN: {error}"));
            return Err(error);
        }
        // Publish live clear only after sealed save, NVRAM/fallback save and
        // authenticated exact readback all succeeded.
        self.st = next;
        self.integrity = None;
        Ok(())
    }

    /// Return the quarantine directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Current quarantine generation counter.
    pub fn generation(&self) -> u64 {
        self.st.generation
    }

    /// Why the state is latched without a reported fault, if it is.
    pub fn integrity_failure(&self) -> Option<&str> {
        self.integrity.as_deref()
    }

    /// Whether latched.
    pub fn is_latched(&self) -> bool {
        self.st.latched
    }

    /// Refuse to run enclave work while latched.
    pub fn ensure_clear(&self) -> EnclaveResult<()> {
        if self.st.latched {
            fail!(
                EPERM,
                "HARDWARE_INTEGRITY_QUARANTINE",
                "recovery requires an UnquarantineGrant"
            );
        }
        Ok(())
    }

    /// Classify and record a fault.
    pub fn report(&mut self, f: FaultReport) -> EnclaveResult<Response> {
        self.persistence_ready()?;
        let null_page = f.fault_addr < NULL_PAGE_LIMIT && matches!(f.kind, FaultKind::Segv);
        let resp = if null_page {
            self.st
                .null_faults
                .retain(|t| f.at_ms.saturating_sub(*t) < NULL_BURST_WINDOW_MS);
            self.st.null_faults.push(f.at_ms);
            if self.st.null_faults.len() >= NULL_BURST_COUNT {
                self.st.latched = true;
                Response::Latched
            } else {
                Response::RestartThrottled
            }
        } else {
            // Tag-check / redzone / cookie faults, and non-null wild SEGVs
            // outside tagged or guarded memory, are integrity faults.
            self.strike(f.kind, f.at_ms)
        };
        self.persist()?;
        // A later benign fault or expired strike window cannot authorize
        // respawn after a persistent latch. Only verified recovery clears it.
        Ok(if self.st.latched { Response::Latched } else { resp })
    }

    fn strike(&mut self, kind: FaultKind, at: u64) -> Response {
        self.st
            .strikes
            .retain(|t| at.saturating_sub(*t) < STRIKE_WINDOW_MS);
        self.st.strikes.push(at);
        // SILICON §5.3 / ADR-012: only hardware tag and PAC failures
        // receive L3's immediate latch. Redzone/cookie reports and other
        // non-null faults still consume the shared two-strike history.
        let latch_at = if self.profile == Profile::L3
            && matches!(kind, FaultKind::HeapTag | FaultKind::Pac)
        { 1 } else { 2 };
        if self.st.strikes.len() >= latch_at {
            self.st.latched = true;
            Response::Latched
        } else {
            Response::StrikeDelayRespawn
        }
    }

    /// Clear with a per-host `k`-of-`n` grant over `grant_digest_v2` binding generation and TTL.
    #[allow(clippy::too_many_arguments)]
    pub fn unquarantine_quorum_v2(
        &mut self,
        policy: &QuorumPolicy,
        host_id: &str,
        cdhash: &str,
        generation: u64,
        expires_at_ms: u64,
        sigs: &[QuorumSignature],
        now_ms: u64,
    ) -> EnclaveResult<()> {
        if now_ms > expires_at_ms {
            fail!(
                EACCES,
                "GRANT_EXPIRED",
                "Unquarantine grant expired at {}",
                expires_at_ms
            );
        }
        if generation != self.st.generation {
            fail!(
                EACCES,
                "GRANT_GENERATION_MISMATCH",
                "Grant generation {} does not match current state generation {}",
                generation,
                self.st.generation
            );
        }
        policy.verify(
            &grant_digest_v2(host_id, cdhash, generation, expires_at_ms),
            sigs,
            now_ms,
        )?;
        self.reset()
    }

    /// Clear with a per-host `k`-of-`n` grant over `grant_digest(host_id, cdhash)` (legacy / test support).
    pub fn unquarantine_quorum(
        &mut self,
        policy: &QuorumPolicy,
        host_id: &str,
        cdhash: &str,
        sigs: &[QuorumSignature],
        now_ms: u64,
    ) -> EnclaveResult<()> {
        if policy
            .verify(
                &grant_digest_v2(host_id, cdhash, self.st.generation, u64::MAX),
                sigs,
                now_ms,
            )
            .is_ok()
            || policy
                .verify(&grant_digest(host_id, cdhash), sigs, now_ms)
                .is_ok()
        {
            self.reset()
        } else {
            fail!(
                EACCES,
                "QUORUM_VERIFICATION_FAILED",
                "Invalid signatures for unquarantine grant"
            )
        }
    }

    /// Clear with a TUF-signed fleet grant: target `unquarantine-grant.json`
    /// whose bytes name the fixed binary's `cdhash`.
    pub fn unquarantine_fleet(
        &mut self,
        tuf: &TufClient,
        grant_bytes: &[u8],
        running_cdhash: &str,
        now: i64,
    ) -> EnclaveResult<()> {
        tuf.verify_target("unquarantine-grant.json", grant_bytes, now)?;
        let g: FleetGrant =
            serde_json::from_slice(grant_bytes).map_err(|e| err!(EINVAL, "FLEET_GRANT", "{e}"))?;
        if g.cdhash != running_cdhash {
            fail!(
                EACCES,
                "FLEET_GRANT_CDHASH_MISMATCH",
                "grant is bound to a different binary"
            );
        }
        self.reset()
    }
}

/// Fleet grant body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetGrant {
    /// Fixed binary `cdhash`.
    pub cdhash: String,
    /// Reason / incident.
    pub incident: String,
}

/// Digest signed by per-host grant custodians (v2 binds generation and expiration).
pub fn grant_digest_v2(
    host_id: &str,
    cdhash: &str,
    generation: u64,
    expires_at_ms: u64,
) -> Vec<u8> {
    format!("MCPMac-UnquarantineGrant-v2\0{host_id}\0{cdhash}\0{generation}\0{expires_at_ms}")
        .into_bytes()
}

/// Digest signed by per-host grant custodians (legacy v1).
pub fn grant_digest(host_id: &str, cdhash: &str) -> Vec<u8> {
    format!("MCPMac-UnquarantineGrant-v1\0{host_id}\0{cdhash}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn dir() -> PathBuf {
        std::env::temp_dir().join(format!("mcpmac-q-{}", enclave_core::rng::u64()))
    }

    fn q(p: Profile) -> (Quarantine, PathBuf) {
        let d = dir();
        (Quarantine::open(p, &d).unwrap(), d)
    }

    fn f(kind: FaultKind, fault_addr: u64, at_ms: u64) -> FaultReport {
        FaultReport {
            kind,
            fault_addr,
            at_ms,
        }
    }

    #[test]
    fn null_page_faults_never_latch_until_burst() {
        let (mut q, _) = q(Profile::L1);
        for i in 0..4 {
            assert_eq!(
                q.report(f(FaultKind::Segv, 0x8, i * 1000)).unwrap(),
                Response::RestartThrottled
            );
        }
        assert!(!q.is_latched());
        assert_eq!(
            q.report(f(FaultKind::Segv, 0x10, 5000)).unwrap(),
            Response::Latched
        );
    }

    #[test]
    fn kind_threshold_matrix_preserves_l1_l2_and_limits_l3_immediate_latch_to_heap_and_pac() {
        use Response::{Latched, StrikeDelayRespawn};
        let kinds = [
            (FaultKind::HeapTag, 8),
            (FaultKind::Pac, 8),
            (FaultKind::Redzone, 8),
            (FaultKind::Segv, NULL_PAGE_LIMIT),
        ];
        for (profile, first) in [
            (Profile::L1, [StrikeDelayRespawn; 4]),
            (Profile::L2, [StrikeDelayRespawn; 4]),
            (Profile::L3, [Latched, Latched, StrikeDelayRespawn, StrikeDelayRespawn]),
        ] {
            for ((kind, address), expected) in kinds.into_iter().zip(first) {
                let (mut owner, dir) = q(profile);
                assert_eq!(owner.report(f(kind, address, 1)).unwrap(), expected,
                    "first {profile:?} {kind:?}");
                assert_eq!(owner.is_latched(), expected == Latched);
                assert_eq!(owner.st.strikes, vec![1]);
                assert!(owner.st.null_faults.is_empty(), "only plain null SEGV is benign");
                assert_eq!(owner.report(f(kind, address, 2)).unwrap(), Latched);
                assert_eq!(owner.st.strikes, vec![1, 2]);
                assert_eq!(owner.generation(), 0);
                drop(owner);
                let owner = Quarantine::open(profile, &dir).unwrap();
                assert!(owner.is_latched());
                assert_eq!(owner.st.strikes, vec![1, 2]);
                drop(owner); std::fs::remove_dir_all(dir).unwrap();
            }
        }
    }

    #[test]
    fn kind_threshold_rolling_window_before_at_and_after_boundary_survives_reopen() {
        for profile in [Profile::L1, Profile::L2, Profile::L3] {
            for (delta, expected, expected_history) in [
                (STRIKE_WINDOW_MS - 1, Response::Latched, vec![100, 100 + STRIKE_WINDOW_MS - 1]),
                (STRIKE_WINDOW_MS, Response::StrikeDelayRespawn, vec![100 + STRIKE_WINDOW_MS]),
                (STRIKE_WINDOW_MS + 1, Response::StrikeDelayRespawn, vec![100 + STRIKE_WINDOW_MS + 1]),
            ] {
                let (mut owner, dir) = q(profile);
                assert_eq!(owner.report(f(FaultKind::Redzone, 0x20000, 100)).unwrap(),
                    Response::StrikeDelayRespawn);
                assert_eq!(owner.report(f(FaultKind::Segv, 8, 101)).unwrap(),
                    Response::RestartThrottled);
                drop(owner);
                let mut owner = Quarantine::open(profile, &dir).unwrap();
                assert!(!owner.is_latched()); assert_eq!(owner.st.strikes, vec![100]);
                assert_eq!(owner.st.null_faults, vec![101]);
                assert_eq!(owner.report(f(FaultKind::Segv, NULL_PAGE_LIMIT, 100 + delta)).unwrap(),
                    expected, "{profile:?} elapsed {delta}");
                assert_eq!(owner.st.strikes, expected_history);
                assert_eq!(owner.st.null_faults, vec![101]);
                drop(owner);
                let owner = Quarantine::open(profile, &dir).unwrap();
                assert_eq!(owner.is_latched(), expected == Response::Latched);
                assert_eq!(owner.st.strikes, expected_history);
                assert_eq!(owner.generation(), 0);
                drop(owner); std::fs::remove_dir_all(dir).unwrap();
            }
        }
    }

    #[test]
    fn kind_threshold_mixed_history_is_shared_across_kinds_and_authenticated_restart() {
        for profile in [Profile::L1, Profile::L2, Profile::L3] {
            let mut pairs = vec![
                (FaultKind::Redzone, FaultKind::Segv),
                (FaultKind::Segv, FaultKind::Redzone),
                (FaultKind::Redzone, FaultKind::HeapTag),
                (FaultKind::Segv, FaultKind::Pac),
            ];
            if profile != Profile::L3 {
                pairs.extend([(FaultKind::HeapTag, FaultKind::Redzone),
                    (FaultKind::Pac, FaultKind::Segv)]);
            }
            for (first, second) in pairs {
                let (mut owner, dir) = q(profile);
                assert_eq!(owner.report(f(first, 0x20000, 10)).unwrap(),
                    Response::StrikeDelayRespawn);
                drop(owner);
                let mut owner = Quarantine::open(profile, &dir).unwrap();
                assert_eq!(owner.st.strikes, vec![10]);
                assert_eq!(owner.report(f(second, 0x30000, 20)).unwrap(), Response::Latched,
                    "{profile:?} {first:?} then {second:?}");
                assert_eq!(owner.st.strikes, vec![10, 20]);
                drop(owner);
                let owner = Quarantine::open(profile, &dir).unwrap();
                assert!(owner.is_latched()); assert_eq!(owner.st.strikes, vec![10, 20]);
                drop(owner); std::fs::remove_dir_all(dir).unwrap();
            }
        }
    }

    #[test]
    fn kind_threshold_existing_mach_classifier_outputs_reach_actual_l3_report_policy() {
        // Software composition using public SDK27.2 ARM subtype declarations.
        // This does not qualify decoded message ABI/native delivery, guarded
        // resource/redzone provenance or actual slab CookieFault forwarding.
        let arm64 = cfg!(target_arch = "aarch64");
        let cases = [
            (1, 0x105, 8, if arm64 { FaultKind::Pac } else { FaultKind::Segv }),
            (1, 0x106, 8, if arm64 { FaultKind::HeapTag } else { FaultKind::Segv }),
            (1, 0x107, 0x20000, if arm64 { FaultKind::HeapTag } else { FaultKind::Segv }),
            (1, 0x102, 0x20000, FaultKind::Segv),
            (1, 1, 0x7f00_0001_0000_2000, FaultKind::Segv),
            (2, 0x100, 0x20000, FaultKind::Redzone),
            (2, 0x102, 8, FaultKind::Redzone),
            (12, (2i64 << 32) | 1, 8, FaultKind::Redzone),
            (12, (5i64 << 32) | 1, 0x20000, FaultKind::Redzone),
            (1, 2, 0x20000, FaultKind::Segv),
            (1, 1, 8, FaultKind::Segv),
        ];
        for profile in [Profile::L1, Profile::L2, Profile::L3] {
            for (exception, code0, code1, expected_kind) in cases {
                let (kind, address) = enclave_core::supervisor::classify_mach_exception(exception, code0, code1);
                assert_eq!(kind, expected_kind); assert_eq!(address, code1 as u64);
                let benign = kind == FaultKind::Segv && address < NULL_PAGE_LIMIT;
                let immediate = profile == Profile::L3 && matches!(kind, FaultKind::Pac | FaultKind::HeapTag);
                let first = if benign { Response::RestartThrottled } else if immediate { Response::Latched } else { Response::StrikeDelayRespawn };
                let (mut owner, dir) = q(profile);
                assert_eq!(owner.report(f(kind, address, 100)).unwrap(), first);
                assert_eq!(owner.is_latched(), immediate);
                assert_eq!(owner.st.strikes, if benign { vec![] } else { vec![100] });
                drop(owner);
                let mut owner = Quarantine::open(profile, &dir).unwrap();
                let second = if benign { Response::RestartThrottled } else { Response::Latched };
                assert_eq!(owner.report(f(kind, address, 101)).unwrap(), second);
                assert_eq!(owner.is_latched(), !benign);
                assert_eq!(owner.st.strikes, if benign { vec![] } else { vec![100, 101] });
                drop(owner); std::fs::remove_dir_all(dir).unwrap();
            }
        }
    }

    #[test]
    fn kind_threshold_latched_reports_never_allow_benign_or_expired_integrity_respawn_after_restart() {
        for profile in [Profile::L1, Profile::L2, Profile::L3] {
            for benign_first in [false, true] {
                let (mut owner, dir) = q(profile);
                assert_eq!(owner.report(f(FaultKind::Redzone, 0x20000, 1)).unwrap(),
                    Response::StrikeDelayRespawn);
                assert_eq!(owner.report(f(FaultKind::Redzone, 0x20000, 2)).unwrap(),
                    Response::Latched);
                drop(owner);
                let mut owner = Quarantine::open(profile, &dir).unwrap();
                // Each report and reopen must keep both the durable latch
                // and the supervisor's response closed, even after 24 hours.
                for index in 0..2 {
                    let at = STRIKE_WINDOW_MS + 3 + index;
                    let benign = (index == 0) == benign_first;
                    let (kind, address) = if benign {
                        (FaultKind::Segv, 8)
                    } else {
                        (FaultKind::Redzone, 0x20000)
                    };
                    assert_eq!(owner.report(f(kind, address, at)).unwrap(), Response::Latched);
                    assert!(owner.ensure_clear().unwrap_err().is("HARDWARE_INTEGRITY_QUARANTINE"));
                    drop(owner);
                    owner = Quarantine::open(profile, &dir).unwrap();
                    assert!(owner.is_latched());
                }
                assert_eq!(owner.st.strikes,
                    vec![STRIKE_WINDOW_MS + if benign_first { 4 } else { 3 }]);
                assert_eq!(owner.st.null_faults,
                    vec![STRIKE_WINDOW_MS + if benign_first { 3 } else { 4 }]);
                assert_eq!(owner.generation(), 0);
                drop(owner); std::fs::remove_dir_all(dir).unwrap();
            }
        }
    }

    #[test]
    fn strike_escalation_by_profile() {
        let (mut l2, _) = q(Profile::L2);
        assert_eq!(
            l2.report(f(FaultKind::HeapTag, 0xdead_0000, 0)).unwrap(),
            Response::StrikeDelayRespawn
        );
        // A second strike more than 24h later is again only strike 1.
        assert_eq!(
            l2.report(f(FaultKind::Pac, 0xdead_0000, STRIKE_WINDOW_MS + 1))
                .unwrap(),
            Response::StrikeDelayRespawn
        );
        assert_eq!(
            l2.report(f(FaultKind::Pac, 0xdead_0000, STRIKE_WINDOW_MS + 2))
                .unwrap(),
            Response::Latched
        );
        assert!(l2
            .ensure_clear()
            .unwrap_err()
            .is("HARDWARE_INTEGRITY_QUARANTINE"));
        let (mut l3, _) = q(Profile::L3);
        assert_eq!(
            l3.report(f(FaultKind::HeapTag, 0x4000_0000, 0)).unwrap(),
            Response::Latched
        );
        // L3 null deref still does not latch.
        let (mut l3b, _) = q(Profile::L3);
        assert_eq!(
            l3b.report(f(FaultKind::Segv, 0, 0)).unwrap(),
            Response::RestartThrottled
        );
    }

    #[test]
    fn deleted_tampered_or_rolled_back_state_is_latched_and_quorum_recovers() {
        let (mut q1, d) = q(Profile::L2);
        let clean = std::fs::read(d.join("quarantine.sealed")).unwrap();
        q1.report(f(FaultKind::HeapTag, 0x1_0000_0000, 0)).unwrap();
        drop(q1);
        assert!(!Quarantine::open(Profile::L2, &d).unwrap().is_latched());
        // Restoring the pre-strike file is a rollback.
        let struck = std::fs::read(d.join("quarantine.sealed")).unwrap();
        std::fs::write(d.join("quarantine.sealed"), &clean).unwrap();
        let q2 = Quarantine::open(Profile::L2, &d).unwrap();
        assert!(
            q2.is_latched() && q2.integrity_failure().unwrap().contains("STATE_ROLLBACK"),
            "{:?}",
            q2.integrity_failure()
        );
        // Deleting state and checkpoint does not reset an initialised host.
        for ext in ["sealed", "gen"] {
            std::fs::remove_file(d.join(format!("quarantine.{ext}"))).unwrap();
        }
        let q3 = Quarantine::open(Profile::L2, &d).unwrap();
        assert!(q3.is_latched() && q3.integrity_failure().unwrap().contains("STATE_MISSING"));
        drop(q3);
        // ...and the latch it wrote is durable.
        assert!(Quarantine::open(Profile::L2, &d).unwrap().is_latched());
        // Editing the strike list without the key is tampering.
        let d2 = dir();
        let mut qa = Quarantine::open(Profile::L2, &d2).unwrap();
        qa.report(f(FaultKind::HeapTag, 0x1_0000_0000, 7)).unwrap();
        drop(qa);
        let s = std::fs::read_to_string(d2.join("quarantine.sealed"))
            .unwrap()
            .replace("[7]", "[]");
        std::fs::write(d2.join("quarantine.sealed"), s).unwrap();
        let mut q4 = Quarantine::open(Profile::L2, &d2).unwrap();
        assert!(q4.is_latched() && q4.integrity_failure().unwrap().contains("STATE_TAMPERED"));
        let _ = struck;
        // A 2-of-3 grant bound to host + cdhash clears and re-seals.
        let keys: Vec<SigningKey> = (0..3)
            .map(|_| SigningKey::generate(&mut rand_core::OsRng))
            .collect();
        let pol = QuorumPolicy::new(keys.iter().map(|k| k.verifying_key()).collect(), 2).unwrap();
        let dg = grant_digest("host-1", "cdhash-abc");
        let sig = |k: &SigningKey| QuorumSignature {
            public_key: k.verifying_key().to_bytes().to_vec(),
            signature: k.sign(&dg).to_bytes().to_vec(),
            collected_at_ms: 0,
        };
        assert!(q4
            .unquarantine_quorum(&pol, "host-1", "cdhash-abc", &[sig(&keys[0])], 1)
            .is_err());
        assert!(
            q4.unquarantine_quorum(
                &pol,
                "host-2",
                "cdhash-abc",
                &[sig(&keys[0]), sig(&keys[1])],
                1
            )
            .is_err(),
            "wrong host"
        );
        q4.unquarantine_quorum(
            &pol,
            "host-1",
            "cdhash-abc",
            &[sig(&keys[0]), sig(&keys[1])],
            1,
        )
        .unwrap();
        assert!(!q4.is_latched());
        drop(q4);
        assert!(!Quarantine::open(Profile::L2, &d2).unwrap().is_latched());
        for x in [d, d2] {
            let _ = std::fs::remove_dir_all(x);
        }
    }

    #[test]
    fn legacy_strike_file_is_migrated_or_latched() {
        let legacy = |d: &Path, st: &PersistedHiq, key: &SecretKey32, good_mac: bool| {
            std::fs::create_dir_all(d).unwrap();
            let state = serde_json::to_string(st).unwrap();
            let mac = if good_mac {
                hex::encode(key.mac(state.as_bytes()))
            } else {
                "00".into()
            };
            std::fs::write(
                d.join("zk-strikes.json"),
                serde_json::to_vec(&serde_json::json!({"state": state, "mac": mac})).unwrap(),
            )
            .unwrap();
            std::fs::write(d.join("zk-strikes.key"), key.expose()).unwrap();
        };
        let k = SecretKey32::random();
        // A verified one-strike L2 history carries over: the next strike latches.
        let d = dir();
        legacy(
            &d,
            &PersistedHiq {
                strikes: vec![1],
                ..Default::default()
            },
            &k,
            true,
        );
        let mut q = Quarantine::open(Profile::L2, &d).unwrap();
        assert!(!q.is_latched() && !d.join("zk-strikes.key").exists());
        assert_eq!(
            q.report(f(FaultKind::HeapTag, 0xdead_0000, 2)).unwrap(),
            Response::Latched
        );
        // A verified latch stays latched; an unverifiable file latches.
        let d2 = dir();
        legacy(&d2, &PersistedHiq::latched(), &k, true);
        assert!(Quarantine::open(Profile::L2, &d2).unwrap().is_latched());
        let d3 = dir();
        legacy(&d3, &PersistedHiq::default(), &k, false);
        let q3 = Quarantine::open(Profile::L2, &d3).unwrap();
        assert!(q3.is_latched() && q3.integrity_failure().is_some());
        drop(q3);
        assert!(Quarantine::open(Profile::L2, &d3).unwrap().is_latched());
        for x in [d, d2, d3] {
            let _ = std::fs::remove_dir_all(x);
        }
    }

    fn v2_grant(generation: u64) -> (QuorumPolicy, Vec<QuorumSignature>) {
        let keys: Vec<_> = (1..=3).map(|b| SigningKey::from_bytes(&[b; 32])).collect();
        let policy = QuorumPolicy::new(keys.iter().map(SigningKey::verifying_key).collect(), 2).unwrap();
        let digest = grant_digest_v2("host-reset", "exact-legacy-code", generation, 1_000);
        let signatures = keys[..2].iter().map(|key| QuorumSignature {
            public_key: key.verifying_key().to_bytes().to_vec(),
            signature: key.sign(&digest).to_bytes().to_vec(),
            collected_at_ms: 0,
        }).collect();
        (policy, signatures)
    }

    fn apply_v2(q: &mut Quarantine, generation: u64) -> EnclaveResult<()> {
        let (policy, signatures) = v2_grant(generation);
        q.unquarantine_quorum_v2(&policy, "host-reset", "exact-legacy-code", generation,
            1_000, &signatures, 1)
    }

    fn reset_fixture() -> (Quarantine, PathBuf) {
        let (mut q, dir) = q(Profile::L3);
        assert_eq!(q.report(f(FaultKind::HeapTag, 0x4000_0000, 42)).unwrap(), Response::Latched);
        (q, dir)
    }

    #[test]
    fn complete_v2_recovery_persists_both_exact_stores_and_rejects_consumed_generation() {
        let (mut q, dir) = reset_fixture();
        let (policy, signatures) = v2_grant(0);
        assert!(q.unquarantine_quorum_v2(&policy, "host-reset", "exact-legacy-code", 0,
            1_000, &signatures[..1], 1).is_err());
        assert!(q.is_latched());
        apply_v2(&mut q, 0).unwrap();
        assert!(!q.is_latched()); q.ensure_clear().unwrap();
        assert_eq!(q.generation(), 1);
        let (saved, integrity) = load_hiq(false, &dir, &q.key, true).unwrap();
        assert!(integrity.is_none()); assert_eq!(saved, q.st);
        drop(q);
        let mut q = Quarantine::open(Profile::L3, &dir).unwrap();
        assert!(!q.is_latched()); assert_eq!(q.generation(), 1);
        q.report(f(FaultKind::HeapTag, 0x4000_0000, 43)).unwrap();
        assert!(apply_v2(&mut q, 0).unwrap_err().is("GRANT_GENERATION_MISMATCH"));
        assert!(q.is_latched()); apply_v2(&mut q, 1).unwrap();
        assert_eq!(q.generation(), 2); drop(q);
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn obstruction_refuses_live_clear_and_reopen_preserves_floor(kind: &str) {
        let (mut q, dir) = reset_fixture();
        let path = dir.join(kind);
        let original = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap(); std::fs::create_dir(&path).unwrap();
        let error = apply_v2(&mut q, 0).unwrap_err();
        if kind == "enclave-hiq.nvram.json" {
            assert!(error.is("QUARANTINE_PERSIST_READBACK"), "{error}");
        }
        assert!(q.ensure_clear().unwrap_err().is("HARDWARE_INTEGRITY_QUARANTINE"));
        assert!(q.is_latched() && q.persistence_failed && q.integrity_failure().is_some());
        assert_eq!(q.st.strikes, vec![42]);
        assert_eq!(q.generation(), 1, "uncertain new floor retained by live owner");
        let live_state = q.st.clone();
        assert!(apply_v2(&mut q, 1).unwrap_err().is("QUARANTINE_REOPEN_REQUIRED"));
        assert!(q.report(f(FaultKind::Segv, 8, 44)).unwrap_err().is("QUARANTINE_REOPEN_REQUIRED"));
        assert_eq!(q.st, live_state, "faulted owner cannot mutate uncertain state");
        drop(q);
        std::fs::remove_dir(&path).unwrap(); std::fs::write(&path, original).unwrap();
        let mut q = Quarantine::open(Profile::L3, &dir).unwrap();
        assert!(q.is_latched()); assert_eq!(q.st.strikes, vec![42]);
        let floor = if kind == "quarantine.sealed" { 0 } else { 1 };
        assert_eq!(q.generation(), floor,
            "authenticated partial successor or old NVRAM latch/floor survives restart");
        if floor == 1 {
            assert!(q.integrity_failure().unwrap().contains("STATE_GENERATION_MISMATCH"));
            assert!(apply_v2(&mut q, 0).unwrap_err().is("GRANT_GENERATION_MISMATCH"));
        }
        apply_v2(&mut q, floor).unwrap();
        assert!(!q.is_latched()); assert_eq!(q.generation(), floor + 1);
        drop(q); std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn recovery_sealed_write_failure_retains_live_latch_and_original_restart_state() {
        obstruction_refuses_live_clear_and_reopen_preserves_floor("quarantine.sealed");
    }

    #[test]
    fn recovery_checkpoint_failure_after_state_write_keeps_latch_and_consumed_floor_on_restart() {
        obstruction_refuses_live_clear_and_reopen_preserves_floor("quarantine.gen");
    }

    #[test]
    fn recovery_ignored_fallback_write_failure_is_detected_by_authenticated_exact_readback() {
        obstruction_refuses_live_clear_and_reopen_preserves_floor("enclave-hiq.nvram.json");
    }

    #[test]
    fn exhausted_recovery_generation_refuses_before_any_state_or_store_mutation() {
        let (mut q, dir) = reset_fixture();
        q.st.generation = u64::MAX; q.persist().unwrap();
        let before = q.st.clone(); let integrity = q.integrity.clone();
        let files = ["quarantine.sealed", "quarantine.gen", "enclave-hiq.nvram.json"];
        let bytes: Vec<_> = files.iter().map(|name| std::fs::read(dir.join(name)).unwrap()).collect();
        assert!(apply_v2(&mut q, u64::MAX).unwrap_err().is("QUARANTINE_GENERATION_EXHAUSTED"));
        assert_eq!(q.st, before); assert_eq!(q.integrity, integrity); assert!(!q.persistence_failed);
        assert!(q.is_latched());
        for (name, expected) in files.iter().zip(&bytes) {
            assert_eq!(&std::fs::read(dir.join(name)).unwrap(), expected);
        }
        drop(q);
        let mut q = Quarantine::open(Profile::L3, &dir).unwrap();
        assert_eq!(q.generation(), u64::MAX); assert!(q.is_latched());
        assert!(apply_v2(&mut q, u64::MAX).unwrap_err().is("QUARANTINE_GENERATION_EXHAUSTED"));
        drop(q); std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn authenticated_generation_disagreement_latches_and_preserves_larger_floor_from_either_store() {
        for (sealed_floor, nvram_floor) in [(2, 7), (7, 2)] {
            let (mut q, dir) = reset_fixture();
            q.st.generation = sealed_floor; q.persist().unwrap();
            let mut nvram = q.st.clone(); nvram.generation = nvram_floor;
            save_hiq(false, &dir, &q.key, &nvram).unwrap();
            drop(q);
            let mut q = Quarantine::open(Profile::L3, &dir).unwrap();
            assert!(q.is_latched()); assert_eq!(q.generation(), 7);
            assert!(q.integrity_failure().unwrap().contains("STATE_GENERATION_MISMATCH"));
            let (saved, integrity) = load_hiq(false, &dir, &q.key, true).unwrap();
            assert!(integrity.is_none()); assert_eq!(saved.generation, 7);
            assert!(apply_v2(&mut q, 2).unwrap_err().is("GRANT_GENERATION_MISMATCH"));
            assert!(q.is_latched()); apply_v2(&mut q, 7).unwrap();
            assert_eq!(q.generation(), 8); drop(q);
            let q = Quarantine::open(Profile::L3, &dir).unwrap();
            assert!(!q.is_latched()); assert_eq!(q.generation(), 8);
            drop(q); std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn unauthenticated_nvram_generation_cannot_supply_a_floor_or_clear_latch() {
        let (mut q, dir) = reset_fixture();
        q.st.generation = 4; q.persist().unwrap(); drop(q);
        let path = dir.join("enclave-hiq.nvram.json");
        let mut record: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let mut body: PersistedHiq = serde_json::from_str(record["state"].as_str().unwrap()).unwrap();
        body.generation = u64::MAX; body.latched = false;
        record["state"] = serde_json::Value::String(serde_json::to_string(&body).unwrap());
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        let q = Quarantine::open(Profile::L3, &dir).unwrap();
        assert_eq!(q.generation(), 4); assert!(q.is_latched());
        assert!(q.integrity_failure().unwrap().contains("STATE_TAMPERED"));
        drop(q); std::fs::remove_dir_all(dir).unwrap();
    }
}
