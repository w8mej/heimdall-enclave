//! FS-703 §3.2–§3.4 sequential chained dual-silicon co-signature
//! (`Touch ID SEP → YubiKey CTAP 2.1+`) with the anti-MFA-bombing breaker.
//!
//! 1. Validate the `IntentPayloadV1`; compute `d_JCS` and the SAS.
//! 2. Breaker: at most **1** in-flight ceremony globally, at most **3**
//!    `A3`/`A4` prompts per **60 s**, and `PromptCooldown60s` (entered on
//!    "Report Suspicious Prompt" or `>= 5` consecutive timeouts; session-local,
//!    never written to SEP NVRAM; clearable with a fresh Touch ID).
//! 3. Step 1 — Touch ID via `CoreAuthUI`: verify `σ_SEP` over
//!    `d_JCS ‖ nonce ‖ t_start` under the enrolled `.biometryCurrentSet`
//!    key, with the 500 ms dwell. Cancel ⇒ abort; **the YubiKey is never armed**.
//! 4. Step 2 (`L2`/`L3`) — YubiKey: `clientDataHash = SHA-256(d_JCS ‖ σ_SEP ‖
//!    t_start)`; root-port topology in `L3`; MDS + `24h`/`72h` freshness;
//!    `getAssertion(UP=1[, UV=1 in L3])` + encrypted `hmac-secret` for the tier
//!    PRF; full assertion verification; `t_complete - t_start <= 10 s`.
//! 5. `L3` — the synchronous ZK egress gate must also pass.
//! 6. Output a single-use [`CeremonyGrant`] bound to `d_JCS`.

use std::collections::{BTreeSet, VecDeque};

use enclave_core::error::EnclaveResult;
use enclave_core::profile::{ActionClass, Profile};
use enclave_core::secret::SecretBytes;
use enclave_core::{err, fail};
use enclave_crypto::hpke_envelope::Tier;
use p256::ecdsa::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::biometric::{verify_approval, BiometricOutcome, BiometricPrompt, BiometricProvider};
use crate::clock::Clock;
use crate::ctap::assertion::{verify_assertion, EnrolledCredential, SignCountStore};
use crate::ctap::client::{decrypt_prf, CtapClient};
use crate::ctap::hid::HidDevice;
use crate::ctap::mds::MdsState;
use crate::factors::{required_factors, Factor};
use crate::intent::IntentPayloadV1;
use crate::lease::LeaseTable;
use crate::oidc::OidcVerifier;
use enclave_crypto::multisig::{QuorumPolicy, QuorumSignature};

/// Ceremony hard budget.
pub const CEREMONY_BUDGET_NS: u64 = 10_000_000_000;
/// Prompts allowed per window.
pub const MAX_PROMPTS_PER_WINDOW: usize = 3;
/// Window length.
pub const PROMPT_WINDOW_MS: u64 = 60_000;
/// Cooldown length.
pub const COOLDOWN_MS: u64 = 60_000;
/// Consecutive timeouts that trigger the cooldown.
pub const TIMEOUTS_BEFORE_COOLDOWN: u32 = 5;

/// Synchronous ZK egress gate (FS-705 `L3`).
pub trait EgressGate: std::fmt::Debug {
    /// Approve egress of the action identified by `d_jcs`.
    fn approve(&mut self, d_jcs: &[u8; 32]) -> EnclaveResult<()>;

    /// Approve egress with an optional detokenized payload chunk.
    fn approve_chunk(&mut self, d_jcs: &[u8; 32], chunk: &[u8]) -> EnclaveResult<()> {
        let _ = chunk;
        self.approve(d_jcs)
    }
}

/// The vault tier whose PRF the ceremony should evaluate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrfTier {
    /// `Envelope_A3`.
    A3,
    /// `Envelope_A4`.
    A4,
}

impl PrfTier {
    /// `hmac-secret` salt = SHA-256(tier label).
    pub fn salt(self) -> [u8; 32] {
        let label = match self {
            PrfTier::A3 => enclave_crypto::hpke_envelope::A3::PRF_LABEL,
            PrfTier::A4 => enclave_crypto::hpke_envelope::A4::PRF_LABEL,
        };
        Sha256::digest(label).into()
    }
}

/// Hardware the ceremony may touch.
#[derive(Debug, Default)]
pub struct CeremonyHardware<'a> {
    /// `CoreAuthUI` provider.
    pub biometric: Option<&'a mut dyn BiometricProvider>,
    /// Authenticated existing-PIN helper; used only by L3 PIN-only authenticators.
    pub existing_pin: Option<&'a mut dyn crate::pin::ExistingPinProvider>,
    /// Original ceremony cancellation signal, latched by the lifecycle owner.
    pub pin_cancelled: Option<&'a std::sync::atomic::AtomicBool>,
    /// Trusted start before metadata/provider work; fixtures may start here.
    pub ceremony_start_ns: Option<u64>,
    /// Consuming genuine OIDC approval bound to this exact original ceremony.
    pub oidc_step_up: Option<crate::oidc_acquisition::BoundOidcStepUp>,
    /// Browser-isolated source, invoked only after prompt admission succeeds.
    pub oidc_provider: Option<&'a mut dyn crate::oidc_acquisition::IntentOidcProvider>,
    /// Enrolled SEP `.biometryCurrentSet` public key.
    pub sep_key: Option<VerifyingKey>,
    /// Encrypted SEP biometric key blob (Design D2).
    pub sep_bio_blob: Option<Vec<u8>>,
    /// YubiKey HID device (absent in `L1` / airplane mode).
    pub yubikey: Option<&'a mut dyn HidDevice>,
    /// Enrolled YubiKey credential.
    pub credential: Option<&'a EnrolledCredential>,
    /// MDS allowlist state.
    pub mds: Option<&'a MdsState>,
    /// Persisted counters.
    pub counters: Option<&'a mut SignCountStore>,
    /// `L3` ZK egress gate.
    pub egress: Option<&'a mut dyn EgressGate>,
    /// A2 15-minute lease table.
    pub leases: Option<&'a mut LeaseTable>,
    /// Whether the authenticator is currently yanked / disconnected.
    pub is_yanked: bool,
    /// Explicit in-memory fixture verifier; production uses `oidc_step_up`.
    pub oidc_verifier: Option<&'a dyn OidcVerifier>,
    /// OIDC step-up token.
    pub oidc_token: Option<&'a str>,
    /// Quorum policy for org root mutations (L2/L3 A4).
    pub quorum_policy: Option<&'a QuorumPolicy>,
    /// Collected quorum signatures for org root mutations.
    pub quorum_signatures: Option<&'a [QuorumSignature]>,
}

/// A verified, single-use authorization.
#[derive(Debug)]
pub struct CeremonyGrant {
    /// `d_JCS` this grant is bound to.
    pub d_jcs: [u8; 32],
    /// Action class.
    pub action: ActionClass,
    /// Row bound authorised.
    pub row_count_bound: u64,
    /// Factors proven.
    pub factors: BTreeSet<Factor>,
    /// Tier PRF output (`L2`/`L3` vault unwrap share), zeroized on drop.
    pub prf: Option<SecretBytes>,
    /// `σ_SEP`.
    pub sep_signature: Vec<u8>,
    /// Earliest exclusive authenticated wall expiry, if a factor supplies one.
    /// This never replaces or extends the separate original boot-clock budget.
    pub valid_until_unix: Option<i64>,
    /// Earliest captured authority-only shared boot expiry, independently of
    /// the original complete10s ceremony cap. Derived leases retain this cap.
    pub valid_until_boot_ns: Option<u64>,
    consumed: bool,
}

impl CeremonyGrant {
    /// Pure final-release check; preserve this bound in every derived lease.
    /// Authority/signature refresh belongs outside a serialized byte handoff.
    pub fn check_valid_at(&self, now_unix: i64) -> EnclaveResult<()> {
        if now_unix < 0 || self.valid_until_unix.is_some_and(|expiry| now_unix >= expiry) {
            fail!(ESTALE, "CEREMONY_AUTHORITY_EXPIRED");
        }
        Ok(())
    }
    /// Pure monotonic authority check for final handoff and derived leases.
    pub fn check_valid_at_boot(&self, now_ns: u64) -> EnclaveResult<()> {
        if self.valid_until_boot_ns.is_some_and(|expiry|now_ns>=expiry) {
            fail!(ESTALE,"CEREMONY_AUTHORITY_EXPIRED");
        }
        Ok(())
    }
    /// Consume (single use). A second consumption fails closed.
    pub fn consume(&mut self) -> EnclaveResult<()> {
        if self.consumed {
            fail!(EALREADY, "GRANT_ALREADY_USED");
        }
        self.consumed = true;
        Ok(())
    }
    /// Whether the grant was consumed.
    pub fn is_consumed(&self) -> bool {
        self.consumed
    }
}

/// The ceremony engine (one per `UID 703` process).
#[derive(Debug)]
pub struct CeremonyEngine {
    profile: Profile,
    in_flight: bool,
    prompts: VecDeque<u64>,
    consecutive_timeouts: u32,
    cooldown_until_ms: Option<u64>,
}

impl CeremonyEngine {
    /// New engine for the effective profile.
    pub fn new(profile: Profile) -> Self {
        Self {
            profile,
            in_flight: false,
            prompts: VecDeque::new(),
            consecutive_timeouts: 0,
            cooldown_until_ms: None,
        }
    }

    /// Whether `PromptCooldown60s` is active.
    pub fn cooldown_active(&self, now_ms: u64) -> bool {
        self.cooldown_until_ms.is_some_and(|u| now_ms < u)
    }

    /// Clear the cooldown locally with a fresh Touch ID.
    pub fn clear_cooldown(
        &mut self,
        bio: &mut dyn BiometricProvider,
        sep_key: &VerifyingKey,
        sep_blob: &[u8],
        clock: &dyn Clock,
    ) -> EnclaveResult<()> {
        let mut nonce = vec![0u8; 32];
        enclave_core::rng::fill(&mut nonce);
        let p = BiometricPrompt {
            localized_reason: "Clear depot prompt cooldown".into(),
            d_jcs: Sha256::digest(b"depot-ClearCooldown-v1").to_vec(),
            nonce,
            t_start_ns: clock.now_ns(),
            bio_key_blob: sep_blob.to_vec(),
        };
        verify_approval(sep_key, &p, &bio.evaluate(&p))?;
        self.cooldown_until_ms = None;
        self.consecutive_timeouts = 0;
        Ok(())
    }

    /// Cooldown and single-flight bind every ceremony; the prompt rate limit
    /// counts ceremonies that will prompt (`count`).
    fn admit(&mut self, now_ms: u64, count: bool) -> EnclaveResult<()> {
        if self.cooldown_active(now_ms) {
            fail!(EAGAIN, "PROMPT_COOLDOWN_60S");
        }
        if self.in_flight {
            fail!(EAGAIN, "CEREMONY_IN_FLIGHT", "SERIALIZED_SINGLEFLIGHT");
        }
        if count {
            self.count_prompt(now_ms)?;
        }
        Ok(())
    }

    /// Anti-prompt-bombing: at most three prompts per 60 s window.
    fn count_prompt(&mut self, now_ms: u64) -> EnclaveResult<()> {
        while self
            .prompts
            .front()
            .is_some_and(|t| now_ms.saturating_sub(*t) >= PROMPT_WINDOW_MS)
        {
            self.prompts.pop_front();
        }
        if self.prompts.len() >= MAX_PROMPTS_PER_WINDOW {
            fail!(EAGAIN, "PROMPT_RATE_LIMIT", "max 3 A3/A4 prompts per 60 s");
        }
        self.prompts.push_back(now_ms);
        Ok(())
    }

    fn note_outcome(&mut self, o: &BiometricOutcome, now_ms: u64) {
        match o {
            BiometricOutcome::TimedOut => {
                self.consecutive_timeouts += 1;
                if self.consecutive_timeouts >= TIMEOUTS_BEFORE_COOLDOWN {
                    self.cooldown_until_ms = Some(now_ms + COOLDOWN_MS);
                }
            }
            BiometricOutcome::ReportSuspicious => {
                self.cooldown_until_ms = Some(now_ms + COOLDOWN_MS)
            }
            _ => self.consecutive_timeouts = 0,
        }
    }

    /// Run a ceremony for an intent across sensitivity classes `A1`..=`A4`.
    pub fn run(
        &mut self,
        intent: &IntentPayloadV1,
        prf_tier: Option<PrfTier>,
        hw: CeremonyHardware<'_>,
        clock: &dyn Clock,
    ) -> EnclaveResult<CeremonyGrant> {
        self.run_with_counter_checkpoint(intent, prf_tier, hw, clock, &mut |_| Ok(()))
    }

    /// Run with a synchronous durable counter/live-policy checkpoint. Every
    /// verified assertion reaches the checkpoint before PRF decryption or any
    /// grant. Failure retains the advanced in-memory counter and denies use.
    /// Production callers must persist counters and revalidate current policy
    /// here; `run` is the compatible in-memory entrypoint for isolated fixtures.
    pub fn run_with_counter_checkpoint(
        &mut self,
        intent: &IntentPayloadV1,
        prf_tier: Option<PrfTier>,
        hw: CeremonyHardware<'_>,
        clock: &dyn Clock,
        checkpoint: &mut dyn FnMut(&SignCountStore) -> EnclaveResult<()>,
    ) -> EnclaveResult<CeremonyGrant> {
        intent.validate()?;
        if intent.profile != self.profile {
            fail!(
                EPERM,
                "PROFILE_MISMATCH",
                "intent {} vs effective {}",
                intent.profile,
                self.profile
            );
        }
        // A3/A4 always prompt (and A4 may sign in first): count them now. An
        // A2 counts only if its lease does not cover it (see STEP 1).
        self.admit(clock.now_ms(), intent.action_class >= ActionClass::A3)?;
        self.in_flight = true;
        let r = self.run_inner(intent, prf_tier, hw, clock, checkpoint);
        self.in_flight = false;
        r
    }

    fn run_inner(
        &mut self,
        intent: &IntentPayloadV1,
        prf_tier: Option<PrfTier>,
        mut hw: CeremonyHardware<'_>,
        clock: &dyn Clock,
        checkpoint: &mut dyn FnMut(&SignCountStore) -> EnclaveResult<()>,
    ) -> EnclaveResult<CeremonyGrant> {
        let org_root = intent.is_org_root_mutation();
        let need = required_factors(self.profile, intent.action_class, org_root);
        let d_jcs = intent.d_jcs()?;
        let now_ns = clock.now_ns();
        let t_start = hw.ceremony_start_ns.unwrap_or(now_ns);
        if now_ns < t_start {
            fail!(EACCES, "CEREMONY_START_INVALID");
        }
        if intent.action_class >= ActionClass::A3
            && now_ns.saturating_sub(t_start) >= CEREMONY_BUDGET_NS
        {
            fail!(ETIMEDOUT, "CEREMONY_BUDGET_EXCEEDED");
        }
        if need.contains(&Factor::OidcStepUp) && hw.oidc_step_up.is_none() {
            if let Some(provider) = hw.oidc_provider.as_mut() {
                let deadline = t_start.checked_add(CEREMONY_BUDGET_NS)
                    .ok_or_else(|| err!(ETIMEDOUT, "CEREMONY_BUDGET_EXCEEDED"))?;
                let local_cancelled = std::sync::atomic::AtomicBool::new(hw.is_yanked);
                let cancelled = hw.pin_cancelled.unwrap_or(&local_cancelled);
                hw.oidc_step_up = Some(provider.acquire(intent, t_start, deadline, cancelled)?);
                if clock.now_ns().saturating_sub(t_start) >= CEREMONY_BUDGET_NS {
                    fail!(ETIMEDOUT, "CEREMONY_BUDGET_EXCEEDED");
                }
            }
        }
        let mut proven = BTreeSet::from([Factor::SepWorkloadKey]);
        let mut valid_until_unix: Option<i64> = None;
        let mut valid_until_boot_ns: Option<u64> = None;

        // L3 continuous presence check
        if need.contains(&Factor::YubikeyPresent) {
            let present = hw.yubikey.is_some() && !hw.is_yanked;
            if !present {
                fail!(
                    EPERM,
                    "YUBIKEY_NOT_PRESENT",
                    "L3 requires authenticator continuously present"
                );
            }
            proven.insert(Factor::YubikeyPresent);
        }

        // STEP 1: Touch ID (A2, A3, A4)
        let mut sigma_sep = Vec::new();
        let mut verified_biometric_prompt = None;
        if need.contains(&Factor::TouchIdCoreauthui) {
            let mut lease_hit = false;
            let biscuit_root = hex::decode(&intent.canonical_arguments_blake3)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .unwrap_or_else(|| {
                    blake3::hash(intent.canonical_arguments_blake3.as_bytes()).into()
                });

            if intent.action_class == ActionClass::A2 {
                if let Some(leases) = hw.leases.as_ref() {
                    if leases.is_valid(
                        &intent.spiffe_id,
                        intent.target_namespace.as_deref().unwrap_or(""),
                        &biscuit_root,
                        t_start,
                    ) {
                        lease_hit = true;
                    }
                }
            }

            if lease_hit {
                proven.insert(Factor::TouchIdCoreauthui);
            } else {
                if intent.action_class == ActionClass::A2 {
                    self.count_prompt(clock.now_ms())?;
                }
                let bio = hw
                    .biometric
                    .as_mut()
                    .ok_or_else(|| err!(EPERM, "BIOMETRIC_PROVIDER_UNAVAILABLE"))?;
                let sep_key = hw
                    .sep_key
                    .ok_or_else(|| err!(EPERM, "SEP_BIO_KEY_UNAVAILABLE"))?;

                let mut nonce = vec![0u8; 32];
                enclave_core::rng::fill(&mut nonce);
                let prompt = BiometricPrompt {
                    localized_reason: intent.localized_reason()?,
                    d_jcs: d_jcs.to_vec(),
                    nonce,
                    t_start_ns: t_start,
                    bio_key_blob: hw.sep_bio_blob.clone().unwrap_or_default(),
                };
                let outcome = bio.evaluate(&prompt);
                self.note_outcome(&outcome, clock.now_ms());
                sigma_sep = verify_approval(&sep_key, &prompt, &outcome)?;
                verified_biometric_prompt = Some(prompt);
                proven.insert(Factor::TouchIdCoreauthui);

                if intent.action_class == ActionClass::A2 {
                    if let Some(leases) = hw.leases.as_mut() {
                        leases.grant(
                            &intent.spiffe_id,
                            intent.target_namespace.as_deref().unwrap_or(""),
                            biscuit_root,
                            t_start,
                        );
                    }
                }
            }
        }

        if intent.action_class >= ActionClass::A3
            && clock.now_ns().saturating_sub(t_start) >= CEREMONY_BUDGET_NS
        {
            fail!(ETIMEDOUT, "CEREMONY_BUDGET_EXCEEDED");
        }

        // STEP 2: YubiKey (L2/L3 A3/A4)
        let mut prf = None;
        if need.contains(&Factor::YubikeyUp) {
            let dev = hw.yubikey.as_mut().ok_or_else(|| {
                err!(
                    EPERM,
                    "YUBIKEY_REQUIRED",
                    "L2/L3 A3/A4 require the chained YubiKey tap"
                )
            })?;
            let cred = hw
                .credential
                .ok_or_else(|| err!(EPERM, "YUBIKEY_NOT_ENROLLED"))?;
            let mds = hw
                .mds
                .ok_or_else(|| err!(ESTALE, "CUSTODY_METADATA_STALE", "no MDS allowlist loaded"))?;
            let counters = hw
                .counters
                .as_mut()
                .ok_or_else(|| err!(EPERM, "SIGN_COUNT_STORE_UNAVAILABLE"))?;
            if self.profile == Profile::L3 && dev.hub_depth() > 1 {
                fail!(
                    EPERM,
                    "HUB_TOPOLOGY_REJECTED",
                    "L3 keys must be on an Apple root port"
                );
            }
            let remaining = CEREMONY_BUDGET_NS.checked_sub(clock.now_ns().saturating_sub(t_start))
                .filter(|remaining| *remaining > 0)
                .ok_or_else(|| err!(ETIMEDOUT, "CEREMONY_BUDGET_EXCEEDED"))?;
            // Translate the remaining original budget once for injectable test
            // clocks. Every INIT/GetInfo/assertion report shares this deadline.
            let transport_deadline = enclave_core::power::continuous_time_ns().checked_add(remaining)
                .ok_or_else(|| err!(ETIMEDOUT, "CEREMONY_BUDGET_EXCEEDED"))?;
            let mut client = CtapClient::open_with_deadline(&mut **dev, transport_deadline)?;
            let info = client.get_info()?;
            if info.aaguid != cred.aaguid {
                fail!(EACCES, "AAGUID_CHANGED");
            }
            mds.check(
                &info.aaguid,
                info.firmware_version,
                cred.key.alg(),
                self.profile,
                intent.action_class,
                clock.now_unix(),
            )?;
            let mut h = Sha256::new();
            h.update(d_jcs);
            h.update(&sigma_sep);
            h.update(t_start.to_be_bytes());
            let cdh: [u8; 32] = h.finalize().into();
            let require_uv = need.contains(&Factor::YubikeyPinUv);
            let salt = prf_tier.map(PrfTier::salt);
            let (resp, ss) = if require_uv && !info.built_in_uv {
                if self.profile != Profile::L3 { fail!(EPERM, "FIDO_TYPED_PIN_FORBIDDEN_FOR_PROFILE"); }
                let prompt = verified_biometric_prompt.as_ref()
                    .ok_or_else(|| err!(EACCES,"FIDO_PIN_REQUIRES_FRESH_TOUCH_ID"))?;
                let provider = hw.existing_pin.as_mut()
                    .ok_or_else(|| err!(EACCES,"YUBIKEY_PIN_PROVIDER_REQUIRED"))?;
                let local_cancelled = std::sync::atomic::AtomicBool::new(hw.is_yanked);
                let cancelled = hw.pin_cancelled.unwrap_or(&local_cancelled);
                client.get_assertion_with_pin_provider(self.profile, &cred.credential_id, &cdh,
                    salt.as_ref(), transport_deadline, cancelled, || {
                        if clock.now_ns().saturating_sub(t_start) >= CEREMONY_BUDGET_NS {
                            fail!(ETIMEDOUT,"CEREMONY_BUDGET_EXCEEDED");
                        }
                        let pin = provider.read_existing_pin_cancellable(prompt, cancelled)?;
                        if clock.now_ns().saturating_sub(t_start) >= CEREMONY_BUDGET_NS {
                            fail!(ETIMEDOUT,"CEREMONY_BUDGET_EXCEEDED");
                        }
                        Ok(pin)
                    })?
            } else {
                client.get_assertion(&cred.credential_id, &cdh, require_uv, salt.as_ref())?
            };
            let va = verify_assertion(cred, &resp, &cdh, require_uv, counters)?;
            checkpoint(counters)?;
            // The metadata window may expire while waiting for actual user
            // presence. Recheck at use, independently of its initial admission.
            mds.check(&info.aaguid, info.firmware_version, cred.key.alg(),
                self.profile, intent.action_class, clock.now_unix())?;
            if clock.now_ns().saturating_sub(t_start) >= CEREMONY_BUDGET_NS {
                fail!(
                    ETIMEDOUT,
                    "CEREMONY_BUDGET_EXCEEDED",
                    "chained ceremony exceeded 10.0 s"
                );
            }
            let expiry = mds.expires_at.min(mds.refreshed_at.saturating_add(crate::ctap::mds::freshness_window_s(self.profile)));
            valid_until_unix = Some(valid_until_unix.map_or(expiry, |previous| previous.min(expiry)));
            proven.insert(Factor::YubikeyUp);
            if va.user_verified {
                proven.insert(Factor::YubikeyPinUv);
            }
            if let (Some(ss), Some(enc)) = (ss, va.hmac_secret_enc.as_ref()) {
                prf = Some(decrypt_prf(&ss, enc)?);
            } else if prf_tier.is_some() {
                fail!(
                    EACCES,
                    "PRF_MISSING",
                    "authenticator returned no hmac-secret output"
                );
            }
        }

        // STEP 3: OIDC Step-Up (A4 in every profile; inherited L1 authority).
        if need.contains(&Factor::OidcStepUp) {
            let subject = if let Some(approval) = hw.oidc_step_up.take() {
                approval.verify_once(intent, clock.now_unix(), clock.now_ns())?
            } else {
                let verifier = hw
                    .oidc_verifier
                    .ok_or_else(|| err!(EPERM, "OIDC_VERIFIER_UNAVAILABLE"))?;
                let token = hw.oidc_token.ok_or_else(|| {
                    err!(EACCES, "OIDC_TOKEN_REQUIRED", "A4 requires OIDC step-up")
                })?;
                verifier.verify_step_up(token, clock.now_unix())?
            };
            let expiry = subject.valid_until_unix;
            valid_until_unix = Some(valid_until_unix.map_or(expiry, |previous| previous.min(expiry)));
            if let Some(expiry)=subject.valid_until_boot_ns {
                valid_until_boot_ns=Some(valid_until_boot_ns.map_or(expiry,|previous|previous.min(expiry)));
            }
            proven.insert(Factor::OidcStepUp);
        }

        // STEP 4: k-of-n Quorum (L2/L3 A4 org root mutations)
        if need.contains(&Factor::KofnEd25519Quorum) {
            let policy = hw
                .quorum_policy
                .ok_or_else(|| err!(EPERM, "QUORUM_POLICY_UNAVAILABLE"))?;
            let sigs = hw
                .quorum_signatures
                .ok_or_else(|| err!(EACCES, "QUORUM_SIGNATURES_REQUIRED"))?;
            let now_wall_ms = (clock.now_unix().max(0) as u64) * 1000;
            policy.verify(&d_jcs, sigs, now_wall_ms)?;
            proven.insert(Factor::KofnEd25519Quorum);
        }

        // STEP 5: ZK egress gate (L3 A3/A4)
        if need.contains(&Factor::ZkEgressGate) {
            let g = hw
                .egress
                .as_mut()
                .ok_or_else(|| err!(EPERM, "ZK_EGRESS_GATE_UNAVAILABLE"))?;
            g.approve_chunk(&d_jcs, intent.canonical_arguments_blake3.as_bytes())?;
            proven.insert(Factor::ZkEgressGate);
        }

        if !need.is_subset(&proven) {
            fail!(EACCES, "FACTORS_NOT_SATISFIED");
        }
        if intent.action_class >= ActionClass::A3
            && clock.now_ns().saturating_sub(t_start) >= CEREMONY_BUDGET_NS
        {
            fail!(ETIMEDOUT, "CEREMONY_BUDGET_EXCEEDED");
        }
        let grant = CeremonyGrant {
            d_jcs,
            action: intent.action_class,
            row_count_bound: intent.row_count_bound.unwrap_or(1),
            factors: proven,
            prf,
            sep_signature: sigma_sep,
            valid_until_unix,
            valid_until_boot_ns,
            consumed: false,
        };
        grant.check_valid_at(clock.now_unix())?;
        grant.check_valid_at_boot(clock.now_ns())?;
        Ok(grant)
    }
}
