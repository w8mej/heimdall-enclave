//! Intent-bound OIDC acquisition from a separately configured browser-isolated
//! broker. This module neither starts a broker nor substitutes a local approval.
//! Missing IdP target, protected broker configuration, current session or genuine
//! nonce-bearing IdP token refuses. Browser OAuth/PKCE implementation remains a
//! separately required source component before this path can work in deployment.

use std::{io::{Read, Write}, path::{Path, PathBuf}, sync::atomic::{AtomicBool, Ordering}};
use ed25519_dalek::VerifyingKey;
use enclave_core::{codesign::CodeRequirement, daemon::DaemonId, error::EnclaveResult,
    custody_metadata::{CustodyTarget, CustodyTargetReceipt},
    custody_lifetime::ReceiptClockAnchor,
    ipc::{Client, Reply}, profile::{ActionClass, Profile}, secret::SecretBytes, err, fail};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use crate::{biometric::DeadlineHelperStream, intent::IntentPayloadV1,
    oidc::{OidcSubject, OidcVerifier, PinnedOidcVerifier, MAX_TOKEN_BYTES}};

/// Fixed independently authenticated TUF target; callers cannot choose it.
pub const OIDC_AUTHORITY_TARGET: &str = "custody-oidc-authority-v1.json";

/// A4 provider boundary, separate from biometric/PIN/key providers.
pub trait IntentOidcProvider: std::fmt::Debug + Send {
    /// Obtain one genuine approval bound to the complete original ceremony.
    fn acquire(&mut self, intent: &IntentPayloadV1, t_start_ns: u64, deadline_ns: u64,
        cancelled: &AtomicBool) -> EnclaveResult<BoundOidcStepUp>;
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    v: u8,
    issuer: String,
    audience: String,
    subject_sha256: String,
    ed25519_public_keys: Vec<String>,
    not_before_unix: i64,
    expires_unix: i64,
}

impl Authority {
    fn parse(bytes: &[u8], now: i64) -> EnclaveResult<Self> {
        if bytes.is_empty() || bytes.len() > 16 * 1024 { fail!(E2BIG, "OIDC_AUTHORITY_SIZE"); }
        let authority: Self = serde_json::from_slice(bytes).map_err(|_| err!(EACCES, "OIDC_AUTHORITY_INVALID"))?;
        authority.verifier(now)?;
        Ok(authority)
    }
    fn verifier(&self, now: i64) -> EnclaveResult<PinnedOidcVerifier> {
        if self.v != 1 || !self.issuer.starts_with("https://") || self.issuer.len() > 2048
            || self.audience.is_empty() || self.audience.len() > 1024
            || self.subject_sha256.len() != 64 || !lower_hex(&self.subject_sha256)
            || self.ed25519_public_keys.is_empty() || self.ed25519_public_keys.len() > 16
            || self.not_before_unix < 0 || now < self.not_before_unix || now >= self.expires_unix
        { fail!(EACCES, "OIDC_AUTHORITY_INVALID"); }
        let mut keys = Vec::new();
        for value in &self.ed25519_public_keys {
            if value.len() != 64 || !lower_hex(value) { fail!(EACCES, "OIDC_AUTHORITY_INVALID"); }
            let bytes: [u8; 32] = hex::decode(value).map_err(|_| err!(EACCES, "OIDC_AUTHORITY_INVALID"))?
                .try_into().map_err(|_| err!(EACCES, "OIDC_AUTHORITY_INVALID"))?;
            let key = VerifyingKey::from_bytes(&bytes).map_err(|_| err!(EACCES, "OIDC_AUTHORITY_INVALID"))?;
            if keys.contains(&key) { fail!(EACCES, "OIDC_AUTHORITY_DUPLICATE_KEY"); }
            keys.push(key);
        }
        Ok(PinnedOidcVerifier::new(&self.issuer, &self.audience, keys))
    }
}

// This IPC assertion is admitted only after authenticating UID702. Keep its
// captured signed-chain/freshness lifetime separate from the authority body.
fn authority_from_receipt(receipt: &CustodyTargetReceipt, profile: Profile, local_now: i64)
    -> EnclaveResult<(Authority, i64)> {
    receipt.validate(local_now, profile, CustodyTarget::OidcAuthority)?;
    let authority = Authority::parse(&receipt.bytes, local_now.max(receipt.verified_now))?;
    Ok((authority, receipt.valid_until_unix(profile)?))
}

fn lower_hex(value: &str) -> bool { value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) }
fn subject_hash(issuer: &str, subject: &str) -> String {
    let mut hash = Sha256::new(); hash.update(b"depot-OIDC-Subject-v1\0");
    hash.update(issuer.as_bytes()); hash.update([0]); hash.update(subject.as_bytes());
    hex::encode(hash.finalize())
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerConfig {
    v: u8,
    socket: PathBuf,
    identifier: String,
    console_uid: u32,
    audit_session_id: u32,
    expires_unix: i64,
}

/// Query actual logged-in, on-console native UID and audit-session metadata.
/// No default or caller-provided identity is accepted; unavailable sessions refuse.
#[cfg(target_os = "macos")]
pub fn current_console_session() -> Option<(u32, u32)> {
    use std::ffi::{c_char, c_void};
    type Ref = *const c_void;
    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" { fn CGSessionCopyCurrentDictionary() -> Ref; }
    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFRelease(value: Ref);
        fn CFGetTypeID(value: Ref) -> usize;
        fn CFStringCreateWithCString(allocator: Ref, text: *const c_char, encoding: u32) -> Ref;
        fn CFDictionaryGetValue(dictionary: Ref, key: Ref) -> Ref;
        fn CFNumberGetTypeID() -> usize;
        fn CFNumberGetValue(number: Ref, kind: isize, value: *mut c_void) -> u8;
        fn CFBooleanGetTypeID() -> usize;
        fn CFBooleanGetValue(value: Ref) -> u8;
    }
    struct Owned(Ref);
    impl Drop for Owned { fn drop(&mut self) { unsafe { CFRelease(self.0) }; } }
    fn value(dictionary: Ref, name: &std::ffi::CStr) -> Option<Ref> {
        let key = unsafe { CFStringCreateWithCString(std::ptr::null(), name.as_ptr(), 0x0800_0100) };
        if key.is_null() { return None; }
        let key = Owned(key);
        let result = unsafe { CFDictionaryGetValue(dictionary, key.0) };
        (!result.is_null()).then_some(result)
    }
    fn number(dictionary: Ref, name: &std::ffi::CStr) -> Option<u32> {
        let value = value(dictionary, name)?;
        if unsafe { CFGetTypeID(value) != CFNumberGetTypeID() } { return None; }
        let mut result: i64 = -1;
        // kCFNumberSInt64Type = 4. Conversion must be exact and nonnegative.
        if unsafe { CFNumberGetValue(value, 4, (&mut result as *mut i64).cast()) } == 0 { return None; }
        u32::try_from(result).ok()
    }
    fn yes(dictionary: Ref, name: &std::ffi::CStr) -> bool {
        value(dictionary, name).is_some_and(|value| unsafe {
            CFGetTypeID(value) == CFBooleanGetTypeID() && CFBooleanGetValue(value) != 0
        })
    }
    let dictionary = unsafe { CGSessionCopyCurrentDictionary() };
    if dictionary.is_null() { return None; }
    let dictionary = Owned(dictionary);
    if !yes(dictionary.0, c"kCGSessionOnConsoleKey") || !yes(dictionary.0, c"kCGSessionLoginDoneKey") {
        return None;
    }
    let uid = number(dictionary.0, c"kCGSessionUserIDKey")?;
    let session = number(dictionary.0, c"kCGSessionAuditIDKey")?;
    (session != 0 && session != u32::MAX
        && enclave_core::runtime_paths::console_uid() == Some(uid)).then_some((uid, session))
}

fn broker_config(path: &Path, now: i64) -> EnclaveResult<(BrokerConfig, [u8; 32])> {
    use std::os::unix::fs::{OpenOptionsExt, MetadataExt};
    if !path.is_absolute() { fail!(EACCES, "OIDC_BROKER_CONFIG_PROTECTION"); }
    for ancestor in path.parent().ok_or_else(|| err!(EACCES, "OIDC_BROKER_CONFIG_PROTECTION"))?.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|_| err!(EACCES, "OIDC_BROKER_CONFIG_PROTECTION"))?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            fail!(EACCES, "OIDC_BROKER_CONFIG_PROTECTION");
        }
    }
    let mut file = std::fs::OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(path)
        .map_err(|_| err!(EACCES, "OIDC_BROKER_CONFIG_PROTECTION"))?;
    let metadata = file.metadata().map_err(|_| err!(EACCES, "OIDC_BROKER_CONFIG_PROTECTION"))?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1 || metadata.len() == 0 || metadata.len() > 4096 {
        fail!(EACCES, "OIDC_BROKER_CONFIG_PROTECTION");
    }
    let mut bytes = Vec::new(); (&mut file).take(4097).read_to_end(&mut bytes)
        .map_err(|_| err!(EIO, "OIDC_BROKER_CONFIG_READ"))?;
    if bytes.len() as u64 != metadata.len() { fail!(EACCES, "OIDC_BROKER_CONFIG_CHANGED"); }
    let config: BrokerConfig = serde_json::from_slice(&bytes).map_err(|_| err!(EACCES, "OIDC_BROKER_CONFIG_INVALID"))?;
    if config.v != 1 || !config.socket.is_absolute() || config.identifier.is_empty()
        || config.identifier.len() > 128 || !config.identifier.bytes().all(|byte| byte.is_ascii_alphanumeric() || b".-".contains(&byte))
        || config.audit_session_id == 0 || config.audit_session_id == u32::MAX || config.expires_unix <= now
        || enclave_core::runtime_paths::console_uid() != Some(config.console_uid)
    { fail!(EACCES, "OIDC_BROKER_SESSION_INVALID"); }
    #[cfg(target_os = "macos")]
    if current_console_session() != Some((config.console_uid, config.audit_session_id)) {
        fail!(EACCES, "OIDC_BROKER_SESSION_INVALID");
    }
    Ok((config, Sha256::digest(&bytes).into()))
}

/// Authenticated one-ceremony approval. It is neither Clone nor serializable;
/// consuming verification is the only way to obtain its checked subject.
pub struct BoundOidcStepUp {
    authority: Authority,
    // Captured from the authenticated CAS target-chain receipt, independently
    // of the document's signed lifetime. Later refresh cannot extend this proof.
    authority_chain_expires_unix: i64,
    authority_deadline_ns: Option<u64>,
    authority_clock: Option<(ReceiptClockAnchor,i64)>,
    token: SecretBytes,
    nonce: String,
    d_jcs: [u8; 32],
    t_start_ns: u64,
    deadline_ns: u64,
    not_before_auth_unix: i64,
    broker: Option<(PathBuf, [u8; 32], u32)>,
}

impl std::fmt::Debug for BoundOidcStepUp {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("BoundOidcStepUp").field("token", &"REDACTED")
            .field("deadline_ns", &self.deadline_ns).finish_non_exhaustive()
    }
}

impl BoundOidcStepUp {
    /// Construct an explicitly software-only signed-token fixture. This is
    /// absent without the test/simulation build mode and establishes no native
    /// session, TUF or IdP enrollment authority. Normal consuming verification
    /// still checks the genuine signature, subject, nonce, intent and times.
    #[cfg(any(test, feature="simulation"))]
    pub fn from_signed_fixture(authority_json: &[u8], token: SecretBytes, nonce: String,
        intent: &IntentPayloadV1, t_start_ns: u64, deadline_ns: u64, not_before_auth_unix: i64)
        -> EnclaveResult<Self> {
        intent.validate()?;
        if intent.action_class!=ActionClass::A4 || deadline_ns<=t_start_ns
            || deadline_ns-t_start_ns>crate::ceremony::CEREMONY_BUDGET_NS
            || token.is_empty() || token.len()>MAX_TOKEN_BYTES || nonce.is_empty() || nonce.len()>256 {
            fail!(EACCES,"OIDC_CEREMONY_BINDING");
        }
        let authority=Authority::parse(authority_json,not_before_auth_unix)?;
        Ok(Self {authority_chain_expires_unix:authority.expires_unix,authority,token,nonce,
            authority_deadline_ns:None,authority_clock:None,
            d_jcs:intent.d_jcs()?,t_start_ns,deadline_ns,not_before_auth_unix,broker:None})
    }

    /// Consume this exact-intent, nonce and principal proof once. Callers supply
    /// their own trusted clocks and still enforce live policy/release generation.
    pub fn verify_once(self, intent: &IntentPayloadV1, now_unix: i64, now_ns: u64) -> EnclaveResult<OidcSubject> {
        if intent.action_class != ActionClass::A4 || intent.d_jcs()? != self.d_jcs
            || now_ns < self.t_start_ns || now_ns >= self.deadline_ns {
            fail!(EACCES, "OIDC_CEREMONY_BINDING");
        }
        if now_unix < 0 || now_unix >= self.authority_chain_expires_unix {
            fail!(ESTALE, "OIDC_AUTHORITY_CHAIN_EXPIRED");
        }
        let mut valid_until_unix = self.authority.expires_unix.min(self.authority_chain_expires_unix);
        if let Some((path, digest, uid)) = &self.broker {
            let (current, observed) = broker_config(path, now_unix)?;
            if observed != *digest || current.console_uid != *uid { fail!(EACCES, "OIDC_BROKER_CONFIG_CHANGED"); }
            valid_until_unix = valid_until_unix.min(current.expires_unix);
        }
        let token = std::str::from_utf8(self.token.expose()).map_err(|_| err!(EACCES, "OIDC_TOKEN_INVALID"))?;
        let mut subject = self.authority.verifier(now_unix)?.verify_step_up(token, now_unix)?;
        if let Some((anchor,observed))=self.authority_clock {
            // Local admission still checks not-before/iat. The separate upper
            // observation additionally rejects token/auth-age expiry that a
            // lagging local clock could otherwise miss; it never relaxes iat.
            let upper=anchor.trusted_upper_unix(observed,now_ns)?.max(now_unix);
            let checked=self.authority.verifier(upper)?.verify_step_up(token,upper)?;
            let captured=anchor.capture_lifetime(subject.valid_until_unix.min(checked.valid_until_unix),observed)?;
            subject.valid_until_unix=captured.valid_until_unix;
            subject.valid_until_boot_ns=Some(self.authority_deadline_ns.map_or(captured.deadline_ns,|bound|bound.min(captured.deadline_ns)));
        } else {
            subject.valid_until_boot_ns=self.authority_deadline_ns;
        }
        if self.not_before_auth_unix < 0 || subject.auth_time < self.not_before_auth_unix {
            fail!(EACCES, "OIDC_FRESH_AUTH_REQUIRED");
        }
        if subject_hash(&subject.iss, &subject.sub) != self.authority.subject_sha256 {
            fail!(EACCES, "OIDC_PRINCIPAL_MISMATCH");
        }
        // The same exact token was already signature/issuer/audience/time checked.
        // A nonce binds fresh IdP authentication to the complete intent/boot and
        // this original ceremony; a cached generic step-up token is insufficient.
        #[derive(Deserialize)] struct Nonce { nonce: String }
        let payload = zeroize::Zeroizing::new(token.split('.').nth(1).and_then(enclave_crypto::b64::dec)
            .ok_or_else(|| err!(EACCES, "OIDC_NONCE_INVALID"))?);
        let claims: Nonce = serde_json::from_slice(&payload).map_err(|_| err!(EACCES, "OIDC_NONCE_INVALID"))?;
        if claims.nonce != self.nonce { fail!(EACCES, "OIDC_NONCE_MISMATCH"); }
        subject.valid_until_unix = subject.valid_until_unix.min(valid_until_unix);
        Ok(subject)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use enclave_core::profile::Profile;
    const NOW: i64 = 1_800_000_000;

    fn intent() -> IntentPayloadV1 {
        IntentPayloadV1 {
            v:1, schema_version:Some("enclave.intent.v1".into()), action_class:ActionClass::A4,
            profile:Profile::L1, data_class:None,
            spiffe_id:"spiffe://corporate.internal/enclave/uid/704".into(),
            tool_name:"depot://analytics/export_csv".into(), target_namespace:Some("dev-billing".into()),
            human_summary_trusted:None,row_count_bound:Some(1),arguments_jcs_sha256:Some("aa".repeat(32)),
            canonical_arguments_blake3:"bb".repeat(32),model_blake3:None,policy_blake3:"cc".repeat(32),
            qif_millibits_delta:Some(0),custody_grant:None,boot_epoch_id:enclave_core::seq::new_boot_epoch_id(),
            rpc_seq_u64:1,ts_utc_ms:NOW as u64*1000,
            required_factors:crate::factors::required_factors(Profile::L1,ActionClass::A4,false).into_iter().collect(),
            user_turn:None,
        }
    }
    fn authority() -> Authority {
        Authority {v:1,issuer:"https://idp.example".into(),audience:"depot".into(),
            subject_sha256:subject_hash("https://idp.example","synthetic-subject"),
            ed25519_public_keys:vec![hex::encode(SigningKey::from_bytes(&[11;32]).verifying_key().as_bytes())],
            not_before_unix:NOW-1,expires_unix:NOW+100}
    }
    fn authority_receipt() -> CustodyTargetReceipt {
        let bytes=serde_json::to_vec(&serde_json::json!({"v":1,"issuer":"https://idp.example","audience":"depot",
            "subject_sha256":subject_hash("https://idp.example","synthetic-subject"),
            "ed25519_public_keys":[hex::encode(SigningKey::from_bytes(&[11;32]).verifying_key().as_bytes())],
            "not_before_unix":NOW-1,"expires_unix":NOW+100})).unwrap();
        CustodyTargetReceipt {v:1,target:OIDC_AUTHORITY_TARGET.into(),
            blake3:blake3::hash(&bytes).to_hex().to_string(),bytes:bytes.into(),
            refreshed_at:NOW-1,expires_at:NOW+200,verified_now:NOW,versions:(1,2,3),effective_profile:Profile::L3}
    }

    #[test]
    fn typed_authority_receipt_checks_target_chain_freshness_bytes_and_observed_time() {
        let receipt=authority_receipt();
        let (authority,until)=authority_from_receipt(&receipt,Profile::L3,NOW).unwrap();
        assert_eq!(authority.expires_unix,NOW+100);assert_eq!(until,NOW+200);
        let mut age=authority_receipt();age.refreshed_at=NOW-24*3600+1;
        assert_eq!(authority_from_receipt(&age,Profile::L3,NOW).unwrap().1,NOW+1);
        assert_eq!(authority_from_receipt(&age,Profile::L1,NOW).unwrap().1,NOW+1,
            "a lower consumer profile cannot extend the authenticated CAS floor");
        assert!(authority_from_receipt(&age,Profile::L3,NOW+1).is_err());
        for mutation in 0..7 {
            let mut value=authority_receipt();
            match mutation {
                0=>value.target=CustodyTarget::EnvelopePolicy.target_name().into(),
                1=>value.expires_at=NOW,
                2=>value.bytes=vec![0].into(),
                3=>value.versions.1=0,
                4=>value.verified_now=NOW+200,
                5=>value.refreshed_at=NOW+1,
                _=>value.v=2,
            }
            assert!(authority_from_receipt(&value,Profile::L3,NOW).is_err());
        }
        let mut future=authority_receipt();future.verified_now=NOW+100;
        assert!(authority_from_receipt(&future,Profile::L3,NOW).unwrap_err().is("OIDC_AUTHORITY_INVALID"));

    }
    fn token(subject:&str,nonce:&str,key:u8) -> SecretBytes {
        token_at(subject, nonce, key, NOW)
    }
    fn token_at(subject:&str,nonce:&str,key:u8,auth_time:i64) -> SecretBytes {
        let header=enclave_crypto::b64::enc(br#"{"alg":"EdDSA","typ":"JWT"}"#);
        let claims=serde_json::json!({"iss":"https://idp.example","aud":"depot","sub":subject,
            "iat":NOW,"auth_time":auth_time,"exp":NOW+60,"nonce":nonce});
        let body=enclave_crypto::b64::enc(&serde_json::to_vec(&claims).unwrap());
        let signed=format!("{header}.{body}");
        let signature=SigningKey::from_bytes(&[key;32]).sign(signed.as_bytes());
        SecretBytes::new(format!("{signed}.{}",enclave_crypto::b64::enc(&signature.to_bytes())).into_bytes())
    }
    fn grant(intent:&IntentPayloadV1,subject:&str,nonce:&str,key:u8) -> BoundOidcStepUp {
        BoundOidcStepUp {authority:authority(),token:token(subject,nonce,key),nonce:"fresh-intent-nonce".into(),
            authority_chain_expires_unix:NOW+100,
            authority_deadline_ns:None,authority_clock:None,
            d_jcs:intent.d_jcs().unwrap(),t_start_ns:100,deadline_ns:10_000_000_100,
            not_before_auth_unix:NOW,broker:None}
    }

    #[test]
    fn software_signed_fixture_constructor_preserves_actual_token_verification() {
        let intent=intent();let receipt=authority_receipt();
        let make=|key|BoundOidcStepUp::from_signed_fixture(&receipt.bytes,
            token("synthetic-subject","fresh-intent-nonce",key),"fresh-intent-nonce".into(),
            &intent,100,10_000_000_100,NOW).unwrap();
        assert!(make(11).verify_once(&intent,NOW,101).is_ok());
        assert!(make(12).verify_once(&intent,NOW,101).unwrap_err().is("OIDC_SIGNATURE_INVALID"));
    }

    #[test]
    fn signed_token_receipt_clock_path_retains_fractional_local_and_boot_caps() {
        let intent=intent();let now=enclave_crypto::time::now_unix();
        let start=enclave_core::clock::boot_clock_ns();let anchor=ReceiptClockAnchor::capture().unwrap();
        let mut authority:serde_json::Value=serde_json::from_slice(&authority_receipt().bytes).unwrap();
        authority["not_before_unix"]=serde_json::json!(now-1);authority["expires_unix"]=serde_json::json!(now+100);
        let header=enclave_crypto::b64::enc(br#"{"alg":"EdDSA","typ":"JWT"}"#);
        let body=enclave_crypto::b64::enc(&serde_json::to_vec(&serde_json::json!({"iss":"https://idp.example",
            "aud":"depot","sub":"synthetic-subject","iat":now,"auth_time":now,"exp":now+60,
            "nonce":"fresh-intent-nonce"})).unwrap());
        let signed=format!("{header}.{body}");let signature=SigningKey::from_bytes(&[11;32]).sign(signed.as_bytes());
        let token=SecretBytes::new(format!("{signed}.{}",enclave_crypto::b64::enc(&signature.to_bytes())).into_bytes());
        let mut proof=BoundOidcStepUp::from_signed_fixture(&serde_json::to_vec(&authority).unwrap(),token,
            "fresh-intent-nonce".into(),&intent,start,start+crate::ceremony::CEREMONY_BUDGET_NS,now).unwrap();
        let captured=anchor.capture_lifetime(now+100,now).unwrap();
        proof.authority_chain_expires_unix=captured.valid_until_unix;proof.authority_deadline_ns=Some(captured.deadline_ns);
        proof.authority_clock=Some((anchor,now));
        let subject=proof.verify_once(&intent,enclave_crypto::time::now_unix(),enclave_core::clock::boot_clock_ns()).unwrap();
        assert!(subject.valid_until_unix<=now+60);
        assert!(subject.valid_until_boot_ns.is_some_and(|bound|bound<=captured.deadline_ns));
    }

    #[test]
    fn bound_oidc_requires_exact_principal_nonce_intent_boot_and_deadline() {
        let intent=intent();
        let value=grant(&intent,"synthetic-subject","fresh-intent-nonce",11);
        assert!(!format!("{value:?}").contains("synthetic-subject"));
        assert_eq!(value.verify_once(&intent,NOW,101).unwrap().sub,"synthetic-subject");
        for (subject,nonce,key,reason) in [
            ("other-subject","fresh-intent-nonce",11,"OIDC_PRINCIPAL_MISMATCH"),
            ("synthetic-subject","previous-intent-nonce",11,"OIDC_NONCE_MISMATCH"),
            ("synthetic-subject","fresh-intent-nonce",12,"OIDC_SIGNATURE_INVALID")
        ] {assert!(grant(&intent,subject,nonce,key).verify_once(&intent,NOW,101).unwrap_err().is(reason));}
        let mut changed=intent.clone();changed.boot_epoch_id=enclave_core::seq::new_boot_epoch_id();
        assert!(grant(&intent,"synthetic-subject","fresh-intent-nonce",11).verify_once(&changed,NOW,101).unwrap_err().is("OIDC_CEREMONY_BINDING"));
        changed=intent.clone();changed.row_count_bound=Some(2);
        assert!(grant(&intent,"synthetic-subject","fresh-intent-nonce",11).verify_once(&changed,NOW,101).is_err());
        for now in [99,10_000_000_100] {assert!(grant(&intent,"synthetic-subject","fresh-intent-nonce",11).verify_once(&intent,NOW,now).unwrap_err().is("OIDC_CEREMONY_BINDING"));}
        // Replaying the old signed token into a new ceremony's nonce refuses.
        let mut next=grant(&intent,"synthetic-subject","fresh-intent-nonce",11);
        next.nonce="next-intent-nonce".into();
        assert!(next.verify_once(&intent,NOW,101).unwrap_err().is("OIDC_NONCE_MISMATCH"));
        // A broker request's max_age=0 is not evidence. Even a genuinely
        // signed new-nonce token must prove authentication since browser start.
        for auth_time in [NOW - 1, NOW - 299] {
            let old_token = token_at("synthetic-subject", "fresh-intent-nonce", 11, auth_time);
            assert!(authority().verifier(NOW).unwrap().verify_step_up(
                std::str::from_utf8(old_token.expose()).unwrap(), NOW).is_ok());
            let mut stale = grant(&intent, "synthetic-subject", "fresh-intent-nonce", 11);
            stale.token = old_token;
            assert!(stale.verify_once(&intent, NOW, 101).unwrap_err().is("OIDC_FRESH_AUTH_REQUIRED"));
        }
    }

    #[test]
    fn oidc_authority_refuses_stale_duplicate_or_substitute_keys() {
        let mut value=authority();assert!(value.verifier(NOW).is_ok());
        value.expires_unix=NOW;assert!(value.verifier(NOW).is_err());
        value=authority();value.not_before_unix=NOW+1;assert!(value.verifier(NOW).is_err());
        value=authority();value.ed25519_public_keys.push(value.ed25519_public_keys[0].clone());
        assert!(value.verifier(NOW).unwrap_err().is("OIDC_AUTHORITY_DUPLICATE_KEY"));
        value=authority();value.subject_sha256="AA".repeat(32);assert!(value.verifier(NOW).is_err());
        assert!(Authority::parse(br#"{"v":1,"v":1}"#,NOW).is_err());
        assert!(Authority::parse(&vec![b'x';16*1024+1],NOW).is_err());
    }

    #[test]
    fn native_oidc_never_uses_unsigned_input_or_unscoped_broker() {
        let mut value=intent();value.action_class=ActionClass::A3;
        value.required_factors=crate::factors::required_factors(value.profile,value.action_class,false).into_iter().collect();
        let mut provider=NativeIntentOidcProvider::new("/nonexistent-cas".into(),"/nonexistent-broker".into());
        let now=enclave_core::clock::boot_clock_ns();
        assert!(provider.acquire(&value,now,now+10_000_000_000,&AtomicBool::new(false)).unwrap_err().is("OIDC_CEREMONY_BINDING"));
        assert!(broker_config(Path::new("relative/untrusted"),NOW).unwrap_err().is("OIDC_BROKER_CONFIG_PROTECTION"));
        assert!(broker_config(Path::new("/tmp/unsigned-oidc-broker.json"),NOW).is_err());
    }

    #[derive(Debug)]
    struct Provider {
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        clock: crate::clock::TestClock,
        delay_ms: u64,
        refuse: bool,
    }
    impl IntentOidcProvider for Provider {
        fn acquire(&mut self, intent: &IntentPayloadV1, start: u64, deadline: u64,
            cancelled: &AtomicBool) -> EnclaveResult<BoundOidcStepUp> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert!(!cancelled.load(Ordering::Acquire));
            assert_eq!(deadline - start, crate::ceremony::CEREMONY_BUDGET_NS);
            self.clock.advance_ms(self.delay_ms);
            if self.refuse { fail!(EACCES, "SYNTHETIC_IDP_REFUSAL"); }
            let mut proof = grant(intent, "synthetic-subject", "fresh-intent-nonce", 11);
            proof.t_start_ns = start; proof.deadline_ns = deadline;
            Ok(proof)
        }
    }

    #[test]
    fn admitted_engine_consumes_genuine_proof_and_keeps_original_budget() {
        use crate::{biometric::{Scripted, ScriptedCoreAuthUi}, ceremony::{CeremonyEngine, CeremonyHardware}, clock::{Clock, TestClock}};
        for delay_ms in [200, 10_000] {
            let clock = TestClock::at(NOW);
            let original_start = clock.now_ns();
            let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mut provider = Provider { calls: calls.clone(), clock: clock.clone(), delay_ms, refuse: false };
            let mut bio = ScriptedCoreAuthUi::new([Scripted::Approve]);
            let key = bio.enrolled_key();
            let result = CeremonyEngine::new(Profile::L1).run(&intent(), None, CeremonyHardware {
                ceremony_start_ns: Some(original_start), oidc_provider: Some(&mut provider),
                biometric: Some(&mut bio), sep_key: Some(key), ..Default::default()
            }, &clock);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            if delay_ms == 200 {
                let proof = result.unwrap();
                assert!(proof.factors.contains(&crate::factors::Factor::OidcStepUp));
                assert!(proof.factors.contains(&crate::factors::Factor::TouchIdCoreauthui));
            } else {
                assert!(result.unwrap_err().is("CEREMONY_BUDGET_EXCEEDED"));
                assert!(bio.shown.is_empty(), "expired acquisition cannot start Touch ID");
            }
        }
    }

    #[test]
    fn genuine_nonce_proof_carries_authority_expiry_through_grant_to_late_handoff() {
        use crate::{biometric::{Scripted, ScriptedCoreAuthUi}, ceremony::{CeremonyEngine,CeremonyHardware}, clock::{Clock,TestClock}};
        let intent=intent();let clock=TestClock::at(NOW);
        let mut proof=grant(&intent,"synthetic-subject","fresh-intent-nonce",11);
        proof.authority.expires_unix=NOW+1;proof.t_start_ns=clock.now_ns();
        proof.deadline_ns=clock.now_ns()+crate::ceremony::CEREMONY_BUDGET_NS;
        let mut bio=ScriptedCoreAuthUi::new([Scripted::Approve]);let key=bio.enrolled_key();
        let mut grant=CeremonyEngine::new(Profile::L1).run(&intent,None,CeremonyHardware {
            ceremony_start_ns:Some(clock.now_ns()),oidc_step_up:Some(proof),biometric:Some(&mut bio),sep_key:Some(key),..Default::default()
        },&clock).unwrap();
        assert_eq!(grant.valid_until_unix,Some(NOW+1));grant.consume().unwrap();
        assert!(grant.check_valid_at(NOW).is_ok());
        clock.advance_ms(1000);
        assert!(clock.now_ns()<11_000_000_000,"independent expiry occurs before original10s cap");
        assert!(grant.check_valid_at(clock.now_unix()).unwrap_err().is("CEREMONY_AUTHORITY_EXPIRED"));
    }

    #[test]
    fn earlier_authenticated_chain_expiry_bounds_genuine_nonce_proof_and_derived_grant() {
        use crate::{biometric::{Scripted, ScriptedCoreAuthUi}, ceremony::{CeremonyEngine,CeremonyHardware}, clock::{Clock,TestClock}};
        let intent=intent();let clock=TestClock::at(NOW);
        let mut receipt=authority_receipt();receipt.expires_at=NOW+4;
        let (authority,raw_until)=authority_from_receipt(&receipt,Profile::L1,NOW).unwrap();
        let anchor=ReceiptClockAnchor::from_observations(clock.now_ns(),std::time::Duration::from_secs(NOW as u64)).unwrap();
        let captured=anchor.capture_lifetime_at(raw_until,receipt.verified_now,
            std::time::Duration::from_secs(NOW as u64),clock.now_ns()).unwrap();
        assert_eq!(captured.valid_until_unix,NOW+3,"integer CAS observation retains upper uncertainty");
        let mut expired=grant(&intent,"synthetic-subject","fresh-intent-nonce",11);
        expired.authority=authority.clone();expired.authority_chain_expires_unix=captured.valid_until_unix;
        // Genuine signed token and authority document remain live at+3.
        assert!(expired.verify_once(&intent,NOW+3,101).unwrap_err().is("OIDC_AUTHORITY_CHAIN_EXPIRED"));
        let mut proof=grant(&intent,"synthetic-subject","fresh-intent-nonce",11);
        proof.authority=authority;proof.authority_chain_expires_unix=captured.valid_until_unix;
        proof.authority_deadline_ns=Some(captured.deadline_ns);
        proof.t_start_ns=clock.now_ns();proof.deadline_ns=clock.now_ns()+crate::ceremony::CEREMONY_BUDGET_NS;
        let mut bio=ScriptedCoreAuthUi::new([Scripted::Approve]);let key=bio.enrolled_key();
        let mut result=CeremonyEngine::new(Profile::L1).run(&intent,None,CeremonyHardware {
            ceremony_start_ns:Some(clock.now_ns()),oidc_step_up:Some(proof),biometric:Some(&mut bio),sep_key:Some(key),..Default::default()
        },&clock).unwrap();
        assert_eq!(result.valid_until_unix,Some(NOW+3));assert_eq!(result.valid_until_boot_ns,Some(captured.deadline_ns));
        result.consume().unwrap();
        // A subsequently refreshed transport receipt cannot mutate this grant.
        receipt.expires_at=NOW+200;receipt.verified_now=NOW+1;
        assert_eq!(authority_from_receipt(&receipt,Profile::L1,NOW+1).unwrap().1,NOW+200);
        assert_eq!(result.valid_until_unix,Some(NOW+3));
        assert!(result.check_valid_at(NOW).is_ok());clock.advance_ms(3000);
        assert!(clock.now_ns()<11_000_000_000);
        assert!(result.check_valid_at(clock.now_unix()).unwrap_err().is("CEREMONY_AUTHORITY_EXPIRED"));
        assert!(result.check_valid_at_boot(clock.now_ns()).unwrap_err().is("CEREMONY_AUTHORITY_EXPIRED"));
        assert!(result.check_valid_at(NOW).is_ok(),"boot cap survives a stale local wall observation");
        let mut clock_ahead=grant(&intent,"synthetic-subject","fresh-intent-nonce",11);
        clock_ahead.t_start_ns=1_000_000_000;clock_ahead.deadline_ns=11_000_000_000;
        clock_ahead.authority_clock=Some((anchor,NOW+59));
        assert!(clock_ahead.verify_once(&intent,NOW,1_000_000_000).unwrap_err().is("OIDC_TOKEN_EXPIRED"),
            "token expiry must also hold at the conservative CAS upper time");
    }

    #[test]
    fn denied_prompt_admission_never_contacts_idp() {
        use crate::{biometric::{Scripted, ScriptedCoreAuthUi}, ceremony::{CeremonyEngine, CeremonyHardware}, clock::{Clock, TestClock}};
        let clock = TestClock::at(NOW);
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut provider = Provider { calls: calls.clone(), clock: clock.clone(), delay_ms: 0, refuse: true };
        let mut engine = CeremonyEngine::new(Profile::L1);
        for _ in 0..3 {
            assert!(engine.run(&intent(), None, CeremonyHardware { oidc_provider: Some(&mut provider),
                ..Default::default() }, &clock).unwrap_err().is("SYNTHETIC_IDP_REFUSAL"));
        }
        assert!(engine.run(&intent(), None, CeremonyHardware { oidc_provider: Some(&mut provider),
            ..Default::default() }, &clock).unwrap_err().is("PROMPT_RATE_LIMIT"));
        assert_eq!(calls.load(Ordering::SeqCst), 3);

        let mut engine = CeremonyEngine::new(Profile::L1);
        provider.refuse = false;
        let mut bio = ScriptedCoreAuthUi::new([Scripted::Report]);
        let key = bio.enrolled_key();
        assert!(engine.run(&intent(), None, CeremonyHardware { oidc_provider: Some(&mut provider),
            biometric: Some(&mut bio), sep_key: Some(key), ..Default::default() }, &clock).is_err());
        assert!(engine.run(&intent(), None, CeremonyHardware { oidc_provider: Some(&mut provider),
            ..Default::default() }, &clock).unwrap_err().is("PROMPT_COOLDOWN_60S"));
        assert_eq!(calls.load(Ordering::SeqCst), 4);

        for start in [clock.now_ns() + 1, clock.now_ns()] {
            let mut engine = CeremonyEngine::new(Profile::L1);
            if start == clock.now_ns() { clock.advance_ms(10_000); }
            assert!(engine.run(&intent(), None, CeremonyHardware { ceremony_start_ns: Some(start),
                oidc_provider: Some(&mut provider), ..Default::default() }, &clock).is_err());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 4, "invalid/expired original start cannot start browser work");
    }
}

/// A configured CAS authority source plus independent protected broker identity.
/// The browser OAuth/PKCE executable must implement the documented typed exchange;
/// an absent/unpinned/wrong-session broker always refuses before receiving facts.
#[derive(Debug)]
pub struct NativeIntentOidcProvider { socket_dir: PathBuf, broker_config: PathBuf }

impl NativeIntentOidcProvider {
    /// Configure existing signed services. This creates no host paths or daemon.
    pub fn new(socket_dir: PathBuf, broker_config: PathBuf) -> Self { Self { socket_dir, broker_config } }
}

fn exchange<Req: Serialize, Resp: DeserializeOwned>(client: Client, request: &Req,
    deadline: u64, cancelled: &AtomicBool, maximum: usize) -> EnclaveResult<Resp> {
    if cancelled.load(Ordering::Acquire) { fail!(EACCES, "OIDC_CEREMONY_CANCELLED"); }
    let mut stream = DeadlineHelperStream::new(client.into_authenticated_stream(), deadline)
        .map_err(|_| err!(EIO, "OIDC_BROKER_IO"))?;
    let mut body = Vec::new(); ciborium::into_writer(request, &mut body).map_err(|_| err!(EINVAL, "OIDC_BROKER_PROTOCOL"))?;
    if body.len() > 16 * 1024 { fail!(E2BIG, "OIDC_BROKER_PROTOCOL"); }
    stream.write_all(&(body.len() as u32).to_be_bytes()).and_then(|_| stream.write_all(&body))
        .map_err(|_| err!(EIO, "OIDC_BROKER_IO"))?;
    let mut length = [0; 4]; stream.read_exact_cancellable(&mut length, cancelled).map_err(|_| err!(EIO, "OIDC_BROKER_IO"))?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > maximum { fail!(E2BIG, "OIDC_BROKER_PROTOCOL"); }
    let mut bytes = zeroize::Zeroizing::new(vec![0; length]);
    stream.read_exact_cancellable(&mut bytes, cancelled).map_err(|_| err!(EIO, "OIDC_BROKER_IO"))?;
    let mut cursor = std::io::Cursor::new(bytes.as_slice());
    let reply: Reply<Resp> = ciborium::from_reader(&mut cursor).map_err(|_| err!(EACCES, "OIDC_BROKER_PROTOCOL"))?;
    if cursor.position() != length as u64 { fail!(EACCES, "OIDC_BROKER_PROTOCOL"); }
    match reply { Reply::Ok(value) => Ok(value), Reply::Err(_) => Err(err!(EACCES, "OIDC_BROKER_REFUSED")) }
}

fn remaining(deadline: u64) -> EnclaveResult<std::time::Duration> {
    let now = enclave_core::clock::boot_clock_ns();
    if now >= deadline { fail!(ETIMEDOUT, "OIDC_CEREMONY_DEADLINE"); }
    Ok(std::time::Duration::from_nanos(deadline - now))
}

impl IntentOidcProvider for NativeIntentOidcProvider {
    fn acquire(&mut self, intent: &IntentPayloadV1, t_start_ns: u64, deadline_ns: u64,
        cancelled: &AtomicBool) -> EnclaveResult<BoundOidcStepUp> {
        intent.validate()?;
        if intent.action_class != ActionClass::A4 || deadline_ns <= t_start_ns
            || deadline_ns - t_start_ns > crate::ceremony::CEREMONY_BUDGET_NS
            || enclave_core::clock::boot_clock_ns() < t_start_ns { fail!(EACCES, "OIDC_CEREMONY_BINDING"); }
        let now = enclave_crypto::time::now_unix();
        let (broker, broker_digest) = broker_config(&self.broker_config, now)?;
        let cas_requirement = CodeRequirement::daemon(DaemonId::SwarmSync);
        let clock_anchor = ReceiptClockAnchor::capture()?;
        let cas = Client::connect_verified_deadline(&self.socket_dir.join(DaemonId::SwarmSync.socket_name()),
            DaemonId::SwarmSync.uid(), Some(&cas_requirement), remaining(deadline_ns)?)?;
        #[derive(Serialize)] enum Fetch { FetchCustodyTarget { target: CustodyTarget } }
        #[derive(Deserialize)] enum CasTarget { CustodyTarget(CustodyTargetReceipt) }
        let CasTarget::CustodyTarget(receipt) = exchange(cas,
            &Fetch::FetchCustodyTarget { target: CustodyTarget::OidcAuthority }, deadline_ns, cancelled, 20 * 1024)?;
        let (authority, authority_chain_expires_unix) = authority_from_receipt(&receipt,
            intent.profile, enclave_crypto::time::now_unix())?;
        let captured=clock_anchor.capture_lifetime(authority_chain_expires_unix
            .min(authority.expires_unix).min(broker.expires_unix),receipt.verified_now)?;
        let authority_chain_expires_unix=captured.valid_until_unix;
        let authority_deadline_ns=Some(captured.deadline_ns);
        let deadline_ns=deadline_ns.min(captured.deadline_ns);
        let requirement = CodeRequirement::pinned_boundary(&broker.identifier)?;
        let client = Client::connect_verified_deadline(&broker.socket, broker.console_uid,
            Some(&requirement), remaining(deadline_ns)?)?;
        #[cfg(target_os="macos")]
        if client.server.audit_token.map(|token| token[6]) != Some(broker.audit_session_id) {
            fail!(EACCES, "OIDC_BROKER_SESSION_INVALID");
        }
        #[cfg(not(target_os="macos"))]
        { let _ = client; fail!(EACCES, "OIDC_NATIVE_SESSION_REQUIRED"); }
        #[cfg(target_os="macos")]
        {
            let d_jcs = intent.d_jcs()?;
            let mut random = [0; 32]; enclave_core::rng::fill(&mut random);
            let mut hash = Sha256::new(); hash.update(b"depot-OIDC-Intent-v1\0"); hash.update(d_jcs);
            hash.update(t_start_ns.to_be_bytes()); hash.update(random);
            hash.update(broker.console_uid.to_be_bytes()); hash.update(broker.audit_session_id.to_be_bytes());
            let nonce = enclave_crypto::b64::enc(&hash.finalize());
            #[derive(Serialize)]
            struct Request<'a> { protocol: &'static str, nonce: &'a str, d_jcs: String,
                boot_epoch_id: &'a str, t_start_ns: u64, deadline_ns: u64,
                console_uid: u32, audit_session_id: u32, max_age_s: u8, issuer: &'a str, audience: &'a str }
            fn token_bytes<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<SecretBytes, D::Error> {
                serde_bytes::ByteBuf::deserialize(deserializer).map(|bytes| SecretBytes::new(bytes.into_vec()))
            }
            #[derive(Deserialize)] #[serde(deny_unknown_fields)]
            struct Response { protocol: String, nonce: String, #[serde(deserialize_with="token_bytes")] token: SecretBytes }
            let request = Request { protocol: "enclave.oidc-step-up.v1", nonce: &nonce, d_jcs: hex::encode(d_jcs),
                boot_epoch_id: &intent.boot_epoch_id, t_start_ns, deadline_ns, console_uid: broker.console_uid,
                audit_session_id: broker.audit_session_id, max_age_s: 0, issuer: &authority.issuer, audience: &authority.audience };
            // Seconds are the signed OIDC claim's resolution. No subsecond
            // freshness or clock-uncertainty qualification is inferred here.
            let not_before_auth_unix = enclave_crypto::time::now_unix();
            if not_before_auth_unix < 0 { fail!(EACCES, "OIDC_FRESH_AUTH_REQUIRED"); }
            let response: Response = exchange(client, &request, deadline_ns, cancelled, MAX_TOKEN_BYTES + 1024)?;
            if response.protocol != "enclave.oidc-step-up.v1" || response.nonce != nonce
                || response.token.is_empty() || response.token.len() > MAX_TOKEN_BYTES
                || enclave_core::runtime_paths::console_uid() != Some(broker.console_uid)
                || cancelled.load(Ordering::Acquire) { fail!(EACCES, "OIDC_CEREMONY_BINDING"); }
            remaining(deadline_ns)?;
            if enclave_crypto::time::now_unix() >= authority_chain_expires_unix {
                fail!(ESTALE, "OIDC_AUTHORITY_CHAIN_EXPIRED");
            }
            Ok(BoundOidcStepUp { authority, authority_chain_expires_unix,authority_deadline_ns,
                authority_clock:Some((clock_anchor,receipt.verified_now)),
                token: response.token, nonce, d_jcs, t_start_ns, deadline_ns,
                not_before_auth_unix,
                broker: Some((self.broker_config.clone(), broker_digest, broker.console_uid)) })
        }
    }
}
