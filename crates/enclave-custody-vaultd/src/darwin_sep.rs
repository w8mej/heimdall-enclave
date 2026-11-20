//! GAP-15 step 1: the bare-metal Secure Enclave spike (FS-703 §8.2.4,
//! ADR-010) and the Security.framework binding the real `DarwinSep` will use.
//!
//! ADR-010 assumes UID 703's SEP keys live in the Data Protection Keychain,
//! which requires a provisioning profile granting `keychain-access-groups`;
//! without it `SecKeyCreateRandomKey` fails with `errSecMissingEntitlement`
//! (`-34018`). The spike measures, on the machine it runs on and in the
//! process context it runs in (user, root, `.app` bundle, UID 703 under
//! launchd), which ways of holding an SEP key work:
//!
//! * `keychain_permanent` — the ADR-010 design: a permanent SEP key in the
//!   Data Protection Keychain.
//! * `ephemeral` — a non-permanent SEP key (never touches the keychain); its
//!   public key, an ECDSA signature verified with `p256`, and an X9.63 ECDH
//!   share compared byte-for-byte with the software model of
//!   `SoftwareSep` (so the simulated and real SEP agree on the KDF).
//! * `blob_restore` — the keychain-free persistence route: the key's
//!   SEP-wrapped token object (`kSecAttrTokenOID`, the blob CryptoKit calls
//!   `dataRepresentation`; only this device's SEP can unwrap it) is re-opened
//!   and must sign for the same public key.
//! * `biometry_acl` — creation with `.privateKeyUsage | .biometryCurrentSet`
//!   (creation needs no finger; `--touch` additionally signs, which prompts).
//!
//! Every Security.framework status is recorded; `errors_34018` counts the
//! `-34018` results. Nothing is written to the keychain on success except by
//! `keychain_permanent`, which deletes its item again.

#[cfg(not(target_os = "macos"))]
use serde_json::json;
use serde_json::Value;

/// Spike options.
#[derive(Debug, Clone, Default)]
pub struct SpikeOptions {
    /// Also use the biometry-protected key (shows a Touch ID prompt).
    pub touch: bool,
}

/// Run the spike. On non-macOS hosts it reports that it cannot run.
pub fn spike(opts: &SpikeOptions) -> Value {
    #[cfg(target_os = "macos")]
    {
        imp::spike(opts)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = opts;
        json!({"spike": "sep", "ran": false, "reason": "the Secure Enclave spike runs on macOS only"})
    }
}

/// Run the GAP-14 biometric spike probe.
pub fn bio_probe(path: &std::path::Path) -> enclave_core::error::EnclaveResult<Value> {
    #[cfg(target_os = "macos")]
    {
        imp::bio_probe(path)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        enclave_core::fail!(EPERM, "NOT_SUPPORTED", "bio-probe is macOS-only");
    }
}

/// `errSecMissingEntitlement`.
pub const ERR_SEC_MISSING_ENTITLEMENT: i64 = -34018;

#[cfg(target_os = "macos")]
pub use darwin::DarwinSep;

/// The real Secure Enclave agent (GAP-15), as chosen by the bare-metal spike.
///
/// The spike (`mcp-enclave sep-spike`, FS-703 §8.2.4) showed on Apple silicon
/// that without a provisioning profile the ADR-010 design — permanent keys
/// in the Data Protection Keychain — fails with `-34018` in every context,
/// while a non-permanent SEP key whose SEP-wrapped token object
/// (`kSecAttrTokenOID`) is stored as a file re-opens to the same key in every
/// context, root included. `DarwinSep` therefore keeps its keys as
/// **SEP-wrapped blobs** in UID 703's private state directory: the private key
/// never exists outside the Secure Enclave, the blob is useless on any other
/// Mac, and the access-control policy is enforced by the SEP itself. The
/// difference from the keychain design is who may *open* the blob on this
/// Mac: file permissions (`0600`, `_piivault`) instead of the
/// `keychain-access-groups` entitlement — so root on this host can use the
/// key. Peers pin the epoch key (GAP-27), so a substituted blob is detected.
///
/// * The epoch key (`epoch.sepkey`, `.privateKeyUsage`, usable after first
///   unlock so the daemon works before login) signs `BootEpoch`s.
/// * The tier ECDH keys must carry `.biometryCurrentSet`, which the SEP can
///   only create and use with a user-session `LAContext` (the spike: `-25293`
///   as root). They arrive with the `_enclaveintent` helper (GAP-14, Phase 2
///   step 2); until then [`crate::sep::SepAgent::ecdh_share`] fails closed
///   (`BIOMETRY_HELPER_REQUIRED`) rather than using a weaker key.
#[cfg(target_os = "macos")]
mod darwin {
    use std::path::{Path, PathBuf};

    use enclave_core::error::EnclaveResult;
    use enclave_core::secret::SecretBytes;
    use enclave_core::{err, fail};

    use super::imp::*;
    use crate::ceremony::PrfTier;
    use crate::sep::SepAgent;

    /// A SEP key handle. `SecKeyRef` is a thread-safe CF object.
    struct SepKey(Cf);
    // SAFETY: Security.framework key objects may be used from any thread.
    unsafe impl Send for SepKey {}

    /// Secure Enclave agent backed by SEP-wrapped key blobs.
    pub struct DarwinSep {
        epoch: SepKey,
        epoch_public: Vec<u8>,
        dir: PathBuf,
    }

    impl std::fmt::Debug for DarwinSep {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DarwinSep")
                .field("dir", &self.dir)
                .field("epoch_public", &hex::encode(&self.epoch_public))
                .finish()
        }
    }

    fn status(code: i64, what: &str) -> enclave_core::error::EnclaveError {
        err!(EACCES, "SEP_OPERATION_FAILED", "{what}: OSStatus {code}")
    }

    fn read(p: &Path) -> EnclaveResult<Option<Vec<u8>>> {
        match std::fs::read(p) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(err!(EIO, "SEP_KEY_READ", "{}: {e}", p.display())),
        }
    }

    impl DarwinSep {
        /// Open (or, on first use, create) the epoch key in `dir`.
        pub fn open(dir: &Path) -> EnclaveResult<Self> {
            enclave_core::fsutil::private_dir(dir)?;
            let (blob_p, pub_p) = (dir.join("epoch.sepkey"), dir.join("epoch.pub"));
            let (key, public) = match (read(&blob_p)?, read(&pub_p)?) {
                (Some(blob), Some(public)) => {
                    let b = cfdata(&blob);
                    let (p, _private, _keep) = sep_params(false, None, None, false, Some(&b));
                    let k = create(&p).map_err(|c| status(c, "re-open epoch key"))?;
                    // A blob of some other SEP key (even a valid one on this
                    // Mac) is refused: the stored public key is the pin.
                    if public_bytes(&k).map_err(|c| status(c, "epoch public key"))? != public {
                        fail!(
                            EACCES,
                            "SEP_KEY_MISMATCH",
                            "{} does not open to the pinned epoch key",
                            blob_p.display()
                        );
                    }
                    (k, public)
                }
                (None, None) => {
                    let has_state = dir.join("vault.bin").exists()
                        || dir.join("vault.sealed").exists()
                        || dir.join("epoch-journal.sealed").exists()
                        || dir
                            .parent()
                            .map(|p| {
                                p.join("vault.bin").exists()
                                    || p.join("vault.sealed").exists()
                                    || p.join("epoch-journal.sealed").exists()
                            })
                            .unwrap_or(false);
                    if has_state {
                        fail!(
                            EACCES,
                            "SEP_KEY_STATE_MISSING",
                            "Pre-existing vault state detected in {}, but SEP epoch key files are missing",
                            dir.display()
                        );
                    }
                    let mut e: CFErrorRef = std::ptr::null();
                    // SAFETY: framework constant, valid flags and out-pointer.
                    let acl = Cf(unsafe {
                        SecAccessControlCreateWithFlags(
                            std::ptr::null(),
                            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                            kSecAccessControlPrivateKeyUsage,
                            &mut e,
                        )
                    });
                    if acl.0.is_null() {
                        return Err(status(take_err(e).unwrap_or(-1), "access control"));
                    }
                    let (p, _private, _keep) = sep_params(false, None, Some(&acl), false, None);
                    let k = create(&p).map_err(|c| status(c, "create epoch key"))?;
                    let blob = token_oid(&k).ok_or_else(|| err!(EIO, "SEP_TOKEN_OID_MISSING"))?;
                    let public = public_bytes(&k).map_err(|c| status(c, "epoch public key"))?;
                    enclave_core::fsutil::write_private(&blob_p, &blob)?;
                    enclave_core::fsutil::write_private(&pub_p, &public)?;
                    (k, public)
                }
                _ => fail!(
                    EACCES,
                    "SEP_KEY_STATE",
                    "one of epoch.sepkey / epoch.pub is missing in {}; re-provision UID 703",
                    dir.display()
                ),
            };
            Ok(Self {
                epoch: SepKey(key),
                epoch_public: public,
                dir: dir.to_owned(),
            })
        }

        fn compute_tier_share(&self, name: &str, label: &[u8]) -> EnclaveResult<SecretBytes> {
            let blob_p = self.dir.join(format!("{name}.sepkey"));
            let peer_p = self.dir.join(format!("{name}_peer.pub"));
            if !blob_p.is_file() || !peer_p.is_file() {
                fail!(
                    EPERM,
                    "ENROLLMENT_REQUIRED",
                    "tier key {name} is not enrolled; run mcp-enclave vault enroll"
                );
            }
            let blob = std::fs::read(&blob_p)
                .map_err(|e| err!(EIO, "TIER_KEY_READ", "{}: {e}", blob_p.display()))?;
            let peer_pub = std::fs::read(&peer_p)
                .map_err(|e| err!(EIO, "TIER_PEER_READ", "{}: {e}", peer_p.display()))?;
            let b = cfdata(&blob);
            let (p, _private, _keep) = sep_params(false, None, None, false, Some(&b));
            let k = create(&p).map_err(|c| status(c, "reopen tier key"))?;
            let shared = ecdh(&k, &peer_pub, label).map_err(|c| status(c, "tier ecdh"))?;
            Ok(SecretBytes::new(shared))
        }

        /// Create the SEP tier keys and peer public keys during custodian enrollment (GAP-14 / Design D2).
        pub fn create_tier_keys(&self) -> EnclaveResult<()> {
            let tiers = ["a3", "a4", "l1_a3", "l1_a4"];
            for name in tiers {
                let blob_p = self.dir.join(format!("{name}.sepkey"));
                let pub_p = self.dir.join(format!("{name}.pub"));
                let peer_p = self.dir.join(format!("{name}_peer.pub"));

                let mut e: CFErrorRef = std::ptr::null();
                // SAFETY: framework constant, valid flags and out-pointer.
                let acl = Cf(unsafe {
                    SecAccessControlCreateWithFlags(
                        std::ptr::null(),
                        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                        kSecAccessControlPrivateKeyUsage,
                        &mut e,
                    )
                });
                if acl.0.is_null() {
                    return Err(status(
                        take_err(e).unwrap_or(-1),
                        "access control for tier key",
                    ));
                }
                let (p, _private, _keep) = sep_params(false, None, Some(&acl), false, None);
                let k = create(&p).map_err(|c| status(c, "create tier key"))?;
                let blob = token_oid(&k).ok_or_else(|| err!(EIO, "SEP_TOKEN_OID_MISSING"))?;
                let public = public_bytes(&k).map_err(|c| status(c, "tier public key"))?;

                let peer_sk = p256::SecretKey::random(&mut rand_core::OsRng);
                let peer_pub = super::sec1(&peer_sk.public_key());

                enclave_core::fsutil::write_private(&blob_p, &blob)?;
                enclave_core::fsutil::write_private(&pub_p, &public)?;
                enclave_core::fsutil::write_private(&peer_p, &peer_pub)?;
            }
            Ok(())
        }
    }

    impl SepAgent for DarwinSep {
        fn ecdh_share(&self, tier: PrfTier) -> EnclaveResult<SecretBytes> {
            match tier {
                PrfTier::A3 => self.compute_tier_share("a3", b"MCPMac-SEP-A3"),
                PrfTier::A4 => self.compute_tier_share("a4", b"MCPMac-SEP-A4"),
            }
        }
        fn l1_secondary_share(&self, tier: PrfTier) -> EnclaveResult<SecretBytes> {
            match tier {
                PrfTier::A3 => self.compute_tier_share("l1_a3", b"MCPMac-SEP-L1-A3"),
                PrfTier::A4 => self.compute_tier_share("l1_a4", b"MCPMac-SEP-L1-A4"),
            }
        }
        fn sign_epoch(&self, msg: &[u8]) -> EnclaveResult<Vec<u8>> {
            sign(&self.epoch.0, msg).map_err(|c| status(c, "sign"))
        }
        fn epoch_public_key(&self) -> Vec<u8> {
            self.epoch_public.clone()
        }
        fn create_tier_keys(&self) -> EnclaveResult<()> {
            DarwinSep::create_tier_keys(self)
        }
        fn dpop_public_jwk(&self) -> serde_json::Value {
            if self.epoch_public.len() == 65 && self.epoch_public[0] == 0x04 {
                let x = &self.epoch_public[1..33];
                let y = &self.epoch_public[33..65];
                serde_json::json!({
                    "crv": "P-256",
                    "kty": "EC",
                    "x": enclave_crypto::b64::enc(x),
                    "y": enclave_crypto::b64::enc(y),
                })
            } else {
                serde_json::json!({})
            }
        }
        fn create_dpop_proof(
            &self,
            htm: &str,
            htu: &str,
            iat: i64,
            jti: &str,
            access_token: Option<&str>,
        ) -> EnclaveResult<String> {
            use sha2::{Digest, Sha256};
            let header = serde_json::json!({
                "typ": "dpop+jwt",
                "alg": "ES256",
                "jwk": self.dpop_public_jwk(),
            });
            let mut claims = serde_json::json!({
                "jti": jti,
                "htm": htm.to_ascii_uppercase(),
                "htu": htu,
                "iat": iat,
            });
            if let Some(t) = access_token {
                claims["ath"] = serde_json::Value::String(enclave_crypto::b64::enc(
                    &Sha256::digest(t.as_bytes()),
                ));
            }
            let h = enclave_crypto::b64::enc(
                &serde_json::to_vec(&header).map_err(|e| err!(EINVAL, "DPOP_ENCODE", "{e}"))?,
            );
            let c = enclave_crypto::b64::enc(
                &serde_json::to_vec(&claims).map_err(|e| err!(EINVAL, "DPOP_ENCODE", "{e}"))?,
            );
            let signing_input = format!("{h}.{c}");
            let der = sign(&self.epoch.0, signing_input.as_bytes())
                .map_err(|c| status(c, "dpop sign"))?;
            let sig = p256::ecdsa::Signature::from_der(&der)
                .map_err(|_| err!(EACCES, "DPOP_BAD_SIGNATURE"))?;
            Ok(format!(
                "{signing_input}.{}",
                enclave_crypto::b64::enc(&sig.to_bytes())
            ))
        }
    }
}

/// Verify a DER ECDSA-P256-SHA256 signature by a SEC1 public key.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn verify_p256(public: &[u8], msg: &[u8], der: &[u8]) -> bool {
    use p256::ecdsa::signature::Verifier;
    let (Ok(vk), Ok(sig)) = (
        p256::ecdsa::VerifyingKey::from_sec1_bytes(public),
        p256::ecdsa::Signature::from_der(der),
    ) else {
        return false;
    };
    vk.verify(msg, &sig).is_ok()
}

/// The software model of an SEP tier share, identical to `SoftwareSep`:
/// one-block ANSI X9.63 KDF with SHA-256 over the ECDH secret
/// (`kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256`, 32 bytes,
/// `SharedInfo = label`), computed from the peer's side.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn software_share(
    peer_sk: &p256::SecretKey,
    sep_public: &[u8],
    label: &[u8],
) -> Option<Vec<u8>> {
    use sha2::{Digest, Sha256};
    let pk = p256::PublicKey::from_sec1_bytes(sep_public).ok()?;
    let z = p256::ecdh::diffie_hellman(peer_sk.to_nonzero_scalar(), pk.as_affine());
    let mut h = Sha256::new();
    h.update(z.raw_secret_bytes());
    h.update(1u32.to_be_bytes());
    h.update(label);
    Some(h.finalize().to_vec())
}

/// SEC1 uncompressed encoding of a P-256 public key.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn sec1(pk: &p256::PublicKey) -> Vec<u8> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    pk.to_encoded_point(false).as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The software model the spike compares the real SEP against is the
    /// same computation as the simulated SEP's (symmetric ECDH + X9.63).
    #[test]
    fn software_model_matches_both_sides_and_signatures_verify() {
        let a = p256::SecretKey::random(&mut rand_core::OsRng);
        let b = p256::SecretKey::random(&mut rand_core::OsRng);
        let ab = software_share(&a, &sec1(&b.public_key()), b"MCPMac-SEP-A3").unwrap();
        let ba = software_share(&b, &sec1(&a.public_key()), b"MCPMac-SEP-A3").unwrap();
        assert_eq!(ab, ba);
        assert_ne!(
            ab,
            software_share(&a, &sec1(&b.public_key()), b"MCPMac-SEP-A4").unwrap()
        );
        use p256::ecdsa::signature::Signer;
        let sk = p256::ecdsa::SigningKey::from(&a);
        let sig: p256::ecdsa::Signature = sk.sign(b"m");
        assert!(verify_p256(
            &sec1(&a.public_key()),
            b"m",
            sig.to_der().as_bytes()
        ));
        assert!(!verify_p256(
            &sec1(&b.public_key()),
            b"m",
            sig.to_der().as_bytes()
        ));
        assert!(
            !spike(&SpikeOptions::default())["ran"]
                .as_bool()
                .unwrap_or(true)
                || cfg!(target_os = "macos")
        );
    }

    #[test]
    fn bio_probe_missing_and_invalid_files_fail_closed() {
        let nonexistent = std::path::Path::new("/tmp/mcpmac-nonexistent-bio-spike.json");
        let err = bio_probe(nonexistent).unwrap_err();
        #[cfg(target_os = "macos")]
        assert!(err.is("BIO_FILE_READ"));
        #[cfg(not(target_os = "macos"))]
        assert!(err.is("NOT_SUPPORTED"));

        #[cfg(target_os = "macos")]
        {
            let tmp = std::path::PathBuf::from(format!(
                "/tmp/mcp-test-bio-{:x}.json",
                enclave_core::rng::u64()
            ));
            std::fs::write(&tmp, b"not json").unwrap();
            assert!(bio_probe(&tmp).unwrap_err().is("BIO_FILE_INVALID"));

            std::fs::write(&tmp, b"{}").unwrap();
            assert!(bio_probe(&tmp).unwrap_err().is("BIO_PARAM_MISSING"));
            let _ = std::fs::remove_file(tmp);
        }
    }
}

#[cfg(target_os = "macos")]
#[allow(non_upper_case_globals, non_snake_case, missing_debug_implementations)]
pub(crate) mod imp {
    use std::ffi::{c_char, c_void};
    use std::path::Path;

    use serde_json::{json, Value};

    pub type CFTypeRef = *const c_void;
    pub type CFStringRef = *const c_void;
    pub type CFDataRef = *const c_void;
    pub type CFDictionaryRef = *const c_void;
    pub type CFMutableDictionaryRef = *mut c_void;
    pub type CFErrorRef = *const c_void;
    pub type CFAllocatorRef = *const c_void;
    pub type CFNumberRef = *const c_void;
    pub type SecKeyRef = *const c_void;
    pub type SecAccessControlRef = *const c_void;
    pub type CFIndex = isize;
    pub type CFOptionFlags = usize;
    pub type OSStatus = i32;

    pub const kCFStringEncodingUTF8: u32 = 0x0800_0100;
    pub const kCFNumberSInt32Type: CFIndex = 3;
    pub const kSecAccessControlPrivateKeyUsage: CFOptionFlags = 1 << 30;
    pub const kSecAccessControlBiometryCurrentSet: CFOptionFlags = 1 << 3;

    #[repr(C)]
    pub struct CFDictionaryCallBacks {
        _opaque: [u8; 0],
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        pub static kCFTypeDictionaryKeyCallBacks: CFDictionaryCallBacks;
        pub static kCFTypeDictionaryValueCallBacks: CFDictionaryCallBacks;
        pub static kCFBooleanTrue: CFTypeRef;
        pub static kCFBooleanFalse: CFTypeRef;
        pub fn CFDictionaryCreateMutable(
            alloc: CFAllocatorRef,
            cap: CFIndex,
            kcb: *const CFDictionaryCallBacks,
            vcb: *const CFDictionaryCallBacks,
        ) -> CFMutableDictionaryRef;
        pub fn CFDictionarySetValue(d: CFMutableDictionaryRef, k: CFTypeRef, v: CFTypeRef);
        pub fn CFDictionaryGetValue(d: CFDictionaryRef, k: CFTypeRef) -> CFTypeRef;
        pub fn CFDataCreate(alloc: CFAllocatorRef, bytes: *const u8, len: CFIndex) -> CFDataRef;
        pub fn CFDataGetLength(d: CFDataRef) -> CFIndex;
        pub fn CFDataGetBytePtr(d: CFDataRef) -> *const u8;
        pub fn CFNumberCreate(alloc: CFAllocatorRef, ty: CFIndex, v: *const c_void) -> CFNumberRef;
        pub fn CFStringCreateWithBytes(
            alloc: CFAllocatorRef,
            bytes: *const u8,
            len: CFIndex,
            enc: u32,
            external: u8,
        ) -> CFStringRef;
        pub fn CFErrorGetCode(e: CFErrorRef) -> CFIndex;
        pub fn CFGetTypeID(t: CFTypeRef) -> usize;
        pub fn CFDataGetTypeID() -> usize;
        pub fn CFRelease(t: CFTypeRef);
    }

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        pub static kSecAttrKeyType: CFStringRef;
        pub static kSecAttrKeyTypeECSECPrimeRandom: CFStringRef;
        pub static kSecAttrKeySizeInBits: CFStringRef;
        pub static kSecAttrKeyClass: CFStringRef;
        pub static kSecAttrKeyClassPublic: CFStringRef;
        pub static kSecAttrTokenID: CFStringRef;
        pub static kSecAttrTokenIDSecureEnclave: CFStringRef;
        pub static kSecAttrIsPermanent: CFStringRef;
        pub static kSecAttrApplicationTag: CFStringRef;
        pub static kSecAttrAccessControl: CFStringRef;
        pub static kSecAttrAccessibleWhenUnlockedThisDeviceOnly: CFStringRef;
        pub static kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly: CFStringRef;
        pub static kSecPrivateKeyAttrs: CFStringRef;
        pub static kSecUseDataProtectionKeychain: CFStringRef;
        pub static kSecClass: CFStringRef;
        pub static kSecClassKey: CFStringRef;
        pub static kSecKeyAlgorithmECDSASignatureMessageX962SHA256: CFStringRef;
        pub static kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256: CFStringRef;
        pub static kSecKeyKeyExchangeParameterRequestedSize: CFStringRef;
        pub static kSecKeyKeyExchangeParameterSharedInfo: CFStringRef;
        pub static kSecUseAuthenticationContext: CFStringRef;
        pub fn SecKeyCreateRandomKey(params: CFDictionaryRef, err: *mut CFErrorRef) -> SecKeyRef;
        pub fn SecKeyCopyPublicKey(key: SecKeyRef) -> SecKeyRef;
        pub fn SecKeyCopyExternalRepresentation(key: SecKeyRef, err: *mut CFErrorRef) -> CFDataRef;
        pub fn SecKeyCopyAttributes(key: SecKeyRef) -> CFDictionaryRef;
        pub fn SecKeyCreateSignature(
            key: SecKeyRef,
            alg: CFStringRef,
            data: CFDataRef,
            err: *mut CFErrorRef,
        ) -> CFDataRef;
        pub fn SecKeyCreateWithData(
            data: CFDataRef,
            attrs: CFDictionaryRef,
            err: *mut CFErrorRef,
        ) -> SecKeyRef;
        pub fn SecKeyCopyKeyExchangeResult(
            key: SecKeyRef,
            alg: CFStringRef,
            public: SecKeyRef,
            params: CFDictionaryRef,
            err: *mut CFErrorRef,
        ) -> CFDataRef;
        pub fn SecAccessControlCreateWithFlags(
            alloc: CFAllocatorRef,
            protection: CFTypeRef,
            flags: CFOptionFlags,
            err: *mut CFErrorRef,
        ) -> SecAccessControlRef;
        pub fn SecItemDelete(query: CFDictionaryRef) -> OSStatus;
    }

    #[link(name = "objc")]
    extern "C" {
        pub fn objc_getClass(name: *const c_char) -> *mut c_void;
        pub fn sel_registerName(name: *const c_char) -> *mut c_void;
        pub fn objc_msgSend();
    }

    #[link(name = "LocalAuthentication", kind = "framework")]
    extern "C" {}

    /// One retain count of a CF object, released on drop.
    pub struct Cf(pub CFTypeRef);
    impl Drop for Cf {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: we own one retain count of a non-null CF object.
                unsafe { CFRelease(self.0) }
            }
        }
    }

    pub fn cfstr(s: &str) -> Cf {
        // SAFETY: valid UTF-8 bytes and length.
        Cf(unsafe {
            CFStringCreateWithBytes(
                std::ptr::null(),
                s.as_ptr(),
                s.len() as CFIndex,
                kCFStringEncodingUTF8,
                0,
            )
        })
    }

    pub fn cfdata(b: &[u8]) -> Cf {
        // SAFETY: valid byte slice.
        Cf(unsafe { CFDataCreate(std::ptr::null(), b.as_ptr(), b.len() as CFIndex) })
    }

    pub fn cfnum(v: i32) -> Cf {
        // SAFETY: points at an i32 for kCFNumberSInt32Type.
        Cf(unsafe {
            CFNumberCreate(
                std::ptr::null(),
                kCFNumberSInt32Type,
                (&v as *const i32).cast(),
            )
        })
    }

    pub fn bytes(d: CFDataRef) -> Vec<u8> {
        if d.is_null() {
            return Vec::new();
        }
        // SAFETY: d is a live CFData.
        unsafe {
            std::slice::from_raw_parts(CFDataGetBytePtr(d), CFDataGetLength(d) as usize).to_vec()
        }
    }

    /// A mutable CF dictionary (keys/values retained by the dictionary).
    pub struct Dict(pub Cf);
    impl Default for Dict {
        fn default() -> Self {
            Self::new()
        }
    }
    impl Dict {
        pub fn new() -> Self {
            // SAFETY: standard CFType callbacks.
            Self(Cf(unsafe {
                CFDictionaryCreateMutable(
                    std::ptr::null(),
                    0,
                    &kCFTypeDictionaryKeyCallBacks,
                    &kCFTypeDictionaryValueCallBacks,
                )
            }))
        }
        pub fn set(&self, k: CFTypeRef, v: CFTypeRef) -> &Self {
            // SAFETY: live dictionary; the dictionary retains k and v.
            unsafe { CFDictionarySetValue(self.0 .0 as CFMutableDictionaryRef, k, v) };
            self
        }
        pub fn ptr(&self) -> CFDictionaryRef {
            self.0 .0
        }
    }

    /// Take a CFError out-parameter: its code (OSStatus for errSecDomain).
    pub fn take_err(e: CFErrorRef) -> Option<i64> {
        if e.is_null() {
            return None;
        }
        // SAFETY: e is a CFError we own.
        let code = unsafe { CFErrorGetCode(e) } as i64;
        drop(Cf(e));
        Some(code)
    }

    /// Key-generation parameters for a P-256 SEP key.
    pub fn sep_params(
        permanent: bool,
        tag: Option<&Cf>,
        acl: Option<&Cf>,
        data_protection: bool,
        token_oid: Option<&Cf>,
    ) -> (Dict, Dict, Vec<Cf>) {
        let keep = Vec::new();
        let p = Dict::new();
        let private = Dict::new();
        // SAFETY: reading framework constants.
        unsafe {
            private.set(
                kSecAttrIsPermanent,
                if permanent {
                    kCFBooleanTrue
                } else {
                    kCFBooleanFalse
                },
            );
            if let Some(t) = tag {
                private.set(kSecAttrApplicationTag, t.0);
            }
            if let Some(a) = acl {
                private.set(kSecAttrAccessControl, a.0);
            }
            p.set(kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
            p.set(kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
            p.set(kSecPrivateKeyAttrs, private.ptr());
            if data_protection {
                p.set(kSecUseDataProtectionKeychain, kCFBooleanTrue);
            }
            if let Some(o) = token_oid {
                // `kSecAttrTokenOID` ("toid"): re-open an existing SEP object.
                p.set(cfstr("toid").0, o.0);
            }
        }
        let n = cfnum(256);
        // SAFETY: reading a framework constant.
        unsafe { p.set(kSecAttrKeySizeInBits, n.0) };
        (p, private, {
            let mut k = keep;
            k.push(n);
            k
        })
    }

    pub fn create(params: &Dict) -> Result<Cf, i64> {
        let mut e: CFErrorRef = std::ptr::null();
        // SAFETY: valid parameter dictionary and out-pointer.
        let k = unsafe { SecKeyCreateRandomKey(params.ptr(), &mut e) };
        if k.is_null() {
            return Err(take_err(e).unwrap_or(-1));
        }
        Ok(Cf(k))
    }

    pub fn public_bytes(key: &Cf) -> Result<Vec<u8>, i64> {
        // SAFETY: live SecKey.
        let pk = Cf(unsafe { SecKeyCopyPublicKey(key.0) });
        if pk.0.is_null() {
            return Err(-1);
        }
        let mut e: CFErrorRef = std::ptr::null();
        // SAFETY: live public key.
        let d = Cf(unsafe { SecKeyCopyExternalRepresentation(pk.0, &mut e) });
        if d.0.is_null() {
            return Err(take_err(e).unwrap_or(-1));
        }
        Ok(bytes(d.0))
    }

    pub fn sign(key: &Cf, msg: &[u8]) -> Result<Vec<u8>, i64> {
        let m = cfdata(msg);
        let mut e: CFErrorRef = std::ptr::null();
        // SAFETY: live key, framework algorithm constant, live data.
        let s = Cf(unsafe {
            SecKeyCreateSignature(
                key.0,
                kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                m.0,
                &mut e,
            )
        });
        if s.0.is_null() {
            return Err(take_err(e).unwrap_or(-1));
        }
        Ok(bytes(s.0))
    }

    /// `kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256` against `peer`
    /// (SEC1 uncompressed), 32 bytes, `SharedInfo = label`.
    pub fn ecdh(key: &Cf, peer: &[u8], label: &[u8]) -> Result<Vec<u8>, i64> {
        let attrs = Dict::new();
        let size = cfnum(256);
        // SAFETY: framework constants.
        unsafe {
            attrs.set(kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
            attrs.set(kSecAttrKeyClass, kSecAttrKeyClassPublic);
            attrs.set(kSecAttrKeySizeInBits, size.0);
        }
        let pd = cfdata(peer);
        let mut e: CFErrorRef = std::ptr::null();
        // SAFETY: SEC1 bytes and attributes for an EC public key.
        let pk = Cf(unsafe { SecKeyCreateWithData(pd.0, attrs.ptr(), &mut e) });
        if pk.0.is_null() {
            return Err(take_err(e).unwrap_or(-1));
        }
        let params = Dict::new();
        let n = cfnum(32);
        let info = cfdata(label);
        // SAFETY: framework constants.
        unsafe {
            params.set(kSecKeyKeyExchangeParameterRequestedSize, n.0);
            params.set(kSecKeyKeyExchangeParameterSharedInfo, info.0);
        }
        let mut e: CFErrorRef = std::ptr::null();
        // SAFETY: live keys and parameters.
        let r = Cf(unsafe {
            SecKeyCopyKeyExchangeResult(
                key.0,
                kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256,
                pk.0,
                params.ptr(),
                &mut e,
            )
        });
        if r.0.is_null() {
            return Err(take_err(e).unwrap_or(-1));
        }
        Ok(bytes(r.0))
    }

    /// The SEP-wrapped token object of a key (`kSecAttrTokenOID`).
    pub fn token_oid(key: &Cf) -> Option<Vec<u8>> {
        // SAFETY: live key.
        let a = Cf(unsafe { SecKeyCopyAttributes(key.0) });
        if a.0.is_null() {
            return None;
        }
        let k = cfstr("toid");
        // SAFETY: live dictionary; the value is borrowed (Get rule).
        let v = unsafe { CFDictionaryGetValue(a.0, k.0) };
        // SAFETY: type check before reading bytes.
        if v.is_null() || unsafe { CFGetTypeID(v) != CFDataGetTypeID() } {
            return None;
        }
        Some(bytes(v))
    }

    fn status(r: &Result<impl Sized, i64>) -> Value {
        match r {
            Ok(_) => json!(0),
            Err(c) => json!(c),
        }
    }

    fn sh(cmd: &str, args: &[&str]) -> String {
        std::process::Command::new(cmd)
            .args(args)
            .output()
            .map(|o| {
                String::from_utf8_lossy(if o.stdout.is_empty() {
                    &o.stderr
                } else {
                    &o.stdout
                })
                .trim()
                .to_owned()
            })
            .unwrap_or_default()
    }

    pub fn spike(opts: &super::SpikeOptions) -> Value {
        let msg = b"MCPMac-SEP-spike-v1";
        let mut errors_34018 = 0u32;
        let mut count = |r: &Value| {
            if r.as_i64() == Some(super::ERR_SEC_MISSING_ENTITLEMENT) {
                errors_34018 += 1;
            }
        };
        let exe = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        // SAFETY: plain getters.
        let (uid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
        let context = json!({
            "uid": uid, "euid": euid, "exe": exe,
            "in_app_bundle": exe.contains(".app/Contents/MacOS/"),
            "macos": sh("/usr/bin/sw_vers", &["-productVersion"]),
            "hw_model": sh("/usr/sbin/sysctl", &["-n", "hw.model"]),
            "codesign": sh("/usr/bin/codesign", &["-dv", &exe]).lines().filter(|l| l.starts_with("Identifier") || l.starts_with("Signature") || l.starts_with("TeamIdentifier") || l.starts_with("CodeDirectory")).collect::<Vec<_>>(),
        });

        // 1. ADR-010 design: permanent key in the Data Protection Keychain.
        let tag = cfdata(b"com.enterprise.enclave.custody.spike");
        let (p, _priv, _keep) = sep_params(true, Some(&tag), None, true, None);
        let r1 = create(&p);
        let s1 = status(&r1);
        count(&s1);
        if r1.is_ok() {
            let q = Dict::new();
            // SAFETY: framework constants.
            unsafe {
                q.set(kSecClass, kSecClassKey);
                q.set(kSecAttrApplicationTag, tag.0);
                q.set(kSecUseDataProtectionKeychain, kCFBooleanTrue);
            }
            // SAFETY: valid query dictionary.
            let _ = unsafe { SecItemDelete(q.ptr()) };
        }
        let keychain_permanent = json!({"create": s1});

        // 2. Ephemeral SEP key: public key, signature, ECDH vs software model.
        let (p, _priv, _keep) = sep_params(false, None, None, false, None);
        let r2 = create(&p);
        let s2 = status(&r2);
        count(&s2);
        let mut ephemeral = json!({"create": s2});
        let mut blob_restore = json!({"skipped": "no ephemeral key"});
        if let Ok(key) = &r2 {
            let public = public_bytes(key);
            let sig = sign(key, msg);
            let peer = p256::SecretKey::random(&mut rand_core::OsRng);
            let peer_pub = super::sec1(&peer.public_key());
            let share = ecdh(key, &peer_pub, b"MCPMac-SEP-A3");
            let (ps, ss, es) = (status(&public), status(&sig), status(&share));
            for s in [&ps, &ss, &es] {
                count(s);
            }
            let pubv = public.clone().unwrap_or_default();
            let sig_ok = sig
                .as_ref()
                .map(|d| super::verify_p256(&pubv, msg, d))
                .unwrap_or(false);
            let kdf_match = share
                .as_ref()
                .ok()
                .zip(super::software_share(&peer, &pubv, b"MCPMac-SEP-A3"))
                .map(|(a, b)| a == &b)
                .unwrap_or(false);
            ephemeral = json!({"create": 0, "public_key": ps, "public_key_len": pubv.len(), "sign": ss, "signature_verifies": sig_ok, "ecdh_x963": es, "ecdh_matches_software_model": kdf_match});

            // 3. Keychain-free persistence: re-open the SEP-wrapped blob.
            blob_restore = match token_oid(key) {
                None => json!({"token_oid": "absent"}),
                Some(blob) => {
                    let b = cfdata(&blob);
                    let (p, _priv, _keep) = sep_params(false, None, None, false, Some(&b));
                    let r = create(&p);
                    let s = status(&r);
                    count(&s);
                    match r {
                        Ok(k2) => {
                            let same_public = public_bytes(&k2).ok() == Some(pubv.clone());
                            let sig2 = sign(&k2, msg);
                            let s2 = status(&sig2);
                            count(&s2);
                            let ok = sig2
                                .as_ref()
                                .map(|d| super::verify_p256(&pubv, msg, d))
                                .unwrap_or(false);
                            json!({"token_oid_len": blob.len(), "reopen": 0, "same_public_key": same_public, "sign": s2, "signature_verifies_with_original_key": ok})
                        }
                        Err(_) => json!({"token_oid_len": blob.len(), "reopen": s}),
                    }
                }
            };
        }

        // 4. Biometry-gated tier key (creation; use only with --touch).
        let mut e: CFErrorRef = std::ptr::null();
        // SAFETY: framework constant, valid flags and out-pointer.
        let acl = Cf(unsafe {
            SecAccessControlCreateWithFlags(
                std::ptr::null(),
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet,
                &mut e,
            )
        });
        let biometry_acl = if acl.0.is_null() {
            json!({"access_control": take_err(e).unwrap_or(-1)})
        } else {
            let (p, _priv, _keep) = sep_params(false, None, Some(&acl), false, None);
            let r = create(&p);
            let s = status(&r);
            count(&s);
            let mut v = json!({"create": s});
            if let (true, Ok(k)) = (opts.touch, &r) {
                let sig = sign(k, msg);
                let ss = status(&sig);
                count(&ss);
                let pubv = public_bytes(k).unwrap_or_default();
                v["sign_with_touch_id"] = ss;
                v["signature_verifies"] = json!(sig
                    .as_ref()
                    .map(|d| super::verify_p256(&pubv, msg, d))
                    .unwrap_or(false));
            }
            v
        };

        json!({
            "spike": "sep", "ran": true, "context": context,
            "keychain_permanent": keychain_permanent,
            "ephemeral": ephemeral,
            "blob_restore": blob_restore,
            "biometry_acl": biometry_acl,
            "errors_34018": errors_34018,
        })
    }

    /// Instantiate an `LAContext` from an `externalizedContext` blob via
    /// `-[LAContext initWithExternalizedContext:]`.
    pub fn lacontext_from_externalized(ext: &Cf) -> Option<Cf> {
        // SAFETY: standard Objective-C runtime calls on macOS.
        unsafe {
            let cls = objc_getClass(c"LAContext".as_ptr());
            if cls.is_null() {
                return None;
            }
            let sel_alloc = sel_registerName(c"alloc".as_ptr());
            let sel_init = sel_registerName(c"initWithExternalizedContext:".as_ptr());
            let send_alloc: extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
                std::mem::transmute(objc_msgSend as *const ());
            let send_init: extern "C" fn(*mut c_void, *mut c_void, *const c_void) -> *mut c_void =
                std::mem::transmute(objc_msgSend as *const ());
            let raw_alloc = send_alloc(cls, sel_alloc);
            if raw_alloc.is_null() {
                return None;
            }
            let raw_init = send_init(raw_alloc, sel_init, ext.0);
            if raw_init.is_null() {
                return None;
            }
            Some(Cf(raw_init))
        }
    }

    /// Parameters for re-opening a SEP key with an authenticated `LAContext`.
    pub fn sep_params_with_auth_context(
        token_oid: Option<&Cf>,
        auth_ctx: &Cf,
    ) -> (Dict, Dict, Vec<Cf>) {
        let (p, private, keep) = sep_params(false, None, None, false, token_oid);
        // SAFETY: framework constant and valid live objects.
        unsafe {
            p.set(kSecUseAuthenticationContext, auth_ctx.0);
            private.set(kSecUseAuthenticationContext, auth_ctx.0);
        }
        (p, private, keep)
    }

    /// ECDH operation with `kSecUseAuthenticationContext`.
    pub fn ecdh_with_auth_context(
        key: &Cf,
        peer: &[u8],
        label: &[u8],
        auth_ctx: &Cf,
    ) -> Result<Vec<u8>, i64> {
        let attrs = Dict::new();
        let size = cfnum(256);
        // SAFETY: framework constants.
        unsafe {
            attrs.set(kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
            attrs.set(kSecAttrKeyClass, kSecAttrKeyClassPublic);
            attrs.set(kSecAttrKeySizeInBits, size.0);
        }
        let pd = cfdata(peer);
        let mut e: CFErrorRef = std::ptr::null();
        // SAFETY: SEC1 bytes and attributes for an EC public key.
        let pk = Cf(unsafe { SecKeyCreateWithData(pd.0, attrs.ptr(), &mut e) });
        if pk.0.is_null() {
            return Err(take_err(e).unwrap_or(-1));
        }
        let params = Dict::new();
        let n = cfnum(32);
        let info = cfdata(label);
        // SAFETY: framework constants and live auth context.
        unsafe {
            params.set(kSecKeyKeyExchangeParameterRequestedSize, n.0);
            params.set(kSecKeyKeyExchangeParameterSharedInfo, info.0);
            params.set(kSecUseAuthenticationContext, auth_ctx.0);
        }
        let mut e: CFErrorRef = std::ptr::null();
        // SAFETY: live keys and parameters.
        let r = Cf(unsafe {
            SecKeyCopyKeyExchangeResult(
                key.0,
                kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256,
                pk.0,
                params.ptr(),
                &mut e,
            )
        });
        if r.0.is_null() {
            return Err(take_err(e).unwrap_or(-1));
        }
        Ok(bytes(r.0))
    }

    /// Run the GAP-14 bare-metal biometric probe (Prompt 2A).
    pub fn bio_probe(path: &Path) -> enclave_core::error::EnclaveResult<Value> {
        let raw = std::fs::read(path)
            .map_err(|e| enclave_core::err!(EIO, "BIO_FILE_READ", "{}: {e}", path.display()))?;
        let input: Value = serde_json::from_slice(&raw)
            .map_err(|e| enclave_core::err!(EINVAL, "BIO_FILE_INVALID", "{e}"))?;

        let blob_hex = input
            .get("blob_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| enclave_core::err!(EINVAL, "BIO_PARAM_MISSING", "blob_hex required"))?;
        let pubkey_hex = input
            .get("pubkey_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                enclave_core::err!(EINVAL, "BIO_PARAM_MISSING", "pubkey_hex required")
            })?;
        let ext_ctx_hex = input
            .get("externalized_context_hex")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let blob = hex::decode(blob_hex).map_err(|_| enclave_core::err!(EINVAL, "HEX_DECODE"))?;
        let pubkey =
            hex::decode(pubkey_hex).map_err(|_| enclave_core::err!(EINVAL, "HEX_DECODE"))?;
        let ext_ctx =
            hex::decode(ext_ctx_hex).map_err(|_| enclave_core::err!(EINVAL, "HEX_DECODE"))?;

        // SAFETY: plain getters.
        let (uid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
        let msg = b"MCPMac-SEP-bio-spike-daemon-v1";

        // Q2(a): Re-open blob without context and attempt to sign
        let blob_cf = cfdata(&blob);
        let (p_no_ctx, _, _) = sep_params(false, None, None, false, Some(&blob_cf));
        let r_no_ctx = create(&p_no_ctx);
        let s_reopen_no_ctx = status(&r_no_ctx);
        let s_sign_no_ctx = if let Ok(k) = &r_no_ctx {
            status(&sign(k, msg))
        } else {
            json!(null)
        };
        let q2_no_context = json!({
            "reopen": s_reopen_no_ctx,
            "sign": s_sign_no_ctx
        });

        // Initialize LAContext from externalized context
        let ext_cf = cfdata(&ext_ctx);
        let la_ctx_opt = if ext_ctx.is_empty() {
            None
        } else {
            lacontext_from_externalized(&ext_cf)
        };

        // Q2(b): Re-open blob with kSecUseAuthenticationContext and attempt to sign
        let mut q2_with_context = json!({
            "externalized_context_len": ext_ctx.len(),
            "la_context_initialized": la_ctx_opt.is_some()
        });
        let mut opt_key_with_ctx: Option<Cf> = None;
        if let Some(la_ctx) = &la_ctx_opt {
            let (p_ctx, _, _) = sep_params_with_auth_context(Some(&blob_cf), la_ctx);
            let r_ctx = create(&p_ctx);
            let s_reopen = status(&r_ctx);
            q2_with_context["reopen"] = s_reopen;
            if let Ok(k) = r_ctx {
                let sig_res = sign(&k, msg);
                let s_sign = status(&sig_res);
                q2_with_context["sign"] = s_sign;
                if let Ok(sig_bytes) = &sig_res {
                    let ok = super::verify_p256(&pubkey, msg, sig_bytes);
                    q2_with_context["signature_len"] = json!(sig_bytes.len());
                    q2_with_context["signature_verifies"] = json!(ok);
                }
                opt_key_with_ctx = Some(k);
            }
        }

        // Q3: ECDH with kSecUseAuthenticationContext
        let mut q3_ecdh = json!({});
        let peer = p256::SecretKey::random(&mut rand_core::OsRng);
        let peer_pub = super::sec1(&peer.public_key());
        if let (Some(k), Some(la_ctx)) = (&opt_key_with_ctx, &la_ctx_opt) {
            let share_res = ecdh_with_auth_context(k, &peer_pub, b"MCPMac-SEP-A3", la_ctx);
            let s_ecdh = status(&share_res);
            q3_ecdh["ecdh"] = s_ecdh;
            if let Ok(share_bytes) = &share_res {
                let expected = super::software_share(&peer, &pubkey, b"MCPMac-SEP-A3");
                let matches = expected.map(|exp| exp == *share_bytes).unwrap_or(false);
                q3_ecdh["share_len"] = json!(share_bytes.len());
                q3_ecdh["matches_software_model"] = json!(matches);
            }
        } else {
            q3_ecdh["skipped"] = json!("key or LAContext unavailable");
        }

        // Q4: Multi-op reuse with same context (single-touch authorization)
        let mut q4_reuse = json!({});
        if let (Some(k), Some(la_ctx)) = (&opt_key_with_ctx, &la_ctx_opt) {
            let msg2 = b"MCPMac-SEP-bio-spike-daemon-reuse";
            let sig2_res = sign(k, msg2);
            let s_sig2 = status(&sig2_res);
            q4_reuse["second_sign"] = s_sig2;
            if let Ok(sig_bytes) = &sig2_res {
                q4_reuse["second_sig_verified"] =
                    json!(super::verify_p256(&pubkey, msg2, sig_bytes));
            }
            let share2_res = ecdh_with_auth_context(k, &peer_pub, b"MCPMac-SEP-A3-second", la_ctx);
            q4_reuse["second_ecdh"] = status(&share2_res);
        } else {
            q4_reuse["skipped"] = json!("key or LAContext unavailable");
        }

        Ok(json!({
            "probe": "bio",
            "ran": true,
            "uid": uid,
            "euid": euid,
            "q1_helper": input.get("q1").cloned().unwrap_or(Value::Null),
            "q2_no_context": q2_no_context,
            "q2_with_context": q2_with_context,
            "q3_ecdh": q3_ecdh,
            "q4_reuse": q4_reuse,
            "timestamp_utc_ms": enclave_crypto::time::now_unix() * 1000
        }))
    }
}
