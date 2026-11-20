//! Peer code identity (GAP-02, ADR-005 / ADR-010, FS-703 §4.1).
//!
//! A UID says *which account* is on the other end of a socket; it does not
//! say *which program*. On macOS every connection's kernel `audit_token_t`
//! (`LOCAL_PEERTOKEN`) is resolved with `SecCodeCopyGuestWithAttributes`,
//! validated with `SecCodeCheckValidity` against a designated requirement
//! (`anchor apple generic` + Team ID + signing identifier), and its `cdhash`
//! is read with `SecCodeCopySigningInformation`. A peer that is not the
//! expected signed binary is refused even when it runs under the right UID,
//! and root is admitted only as the signed operator CLI.
//!
//! Linux is a CI platform without code signing: there the requirement
//! cannot be evaluated, peers carry no [`CodeIdentity`], and policies fall
//! back to the kernel UID check ([`enforced`] is `false`).
//!
//! **Status:** the Security.framework binding below compiles only for
//! `target_os = "macos"` and has not yet been executed on Apple silicon.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::daemon::DaemonId;

/// Signing identifier of the operator CLI (`depot-enclave`), the only process
/// admitted as `uid 0`.
pub const CTL_IDENTIFIER: &str = "com.enterprise.enclave.ctl";

/// Signing identifier of the `_enclaveintent` biometric prompt helper (GAP-14).
pub const INTENT_IDENTIFIER: &str = "com.enterprise.enclave.intent";

/// Signing identifier of the sandboxed CDP browser daemon (GAP-34).
pub const BROWSER_IDENTIFIER: &str = "com.enterprise.enclave.browser";

/// Apple Developer Team ID that signs every enclave binary, set at build
/// time with `depot_SIGNING_TEAM_ID`. Empty selects [`SigningMode::LocalPins`].
pub const TEAM_ID: &str = match option_env!("depot_SIGNING_TEAM_ID") {
    Some(t) => t,
    None => "",
};

/// How peer code is identified (fixed at build time).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningMode {
    /// Developer ID / Apple Development signing: `anchor apple generic` +
    /// Team ID + identifier (+ optional TUF-distributed cdhash allowlists).
    TeamId,
    /// No Team ID (ad-hoc signed install on one Mac, Phase 2 bring-up): a
    /// peer must match its signing identifier **and** the exact cdhash the
    /// installer recorded in the root-owned [`PIN_FILE`]. Without the file
    /// no peer matches.
    LocalPins,
}

/// The build's signing mode.
pub const fn signing_mode() -> SigningMode {
    if TEAM_ID.is_empty() {
        SigningMode::LocalPins
    } else {
        SigningMode::TeamId
    }
}

/// Root-owned `{identifier: [cdhash]}` pins written by the installer
/// (`packaging/macos/install.sh`) in [`SigningMode::LocalPins`].
pub const PIN_FILE: &str = "/Library/Application Support/EnterpriseEnclave/codesign-pins.json";

/// Local cdhash pins (GAP-02 / GAP-36 without a Team ID).
pub mod pins {
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::sync::OnceLock;

    use crate::error::EnclaveResult;
    use crate::{err, fail};

    #[derive(serde::Deserialize)]
    struct PinFile {
        v: u8,
        pins: BTreeMap<String, Vec<String>>,
    }

    fn root_owned_not_writable(p: &Path) -> EnclaveResult<()> {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::symlink_metadata(p)
            .map_err(|e| err!(EACCES, "CODESIGN_PINS_MISSING", "{}: {e}", p.display()))?;
        if m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            fail!(
                EACCES,
                "CODESIGN_PINS_INSECURE",
                "{} must be root-owned, not a symlink, not group/other writable",
                p.display()
            );
        }
        Ok(())
    }

    /// Load and validate a pin file: the file and its directory are
    /// root-owned and not group/other writable; every cdhash is 40 hex.
    pub fn load(path: &Path) -> EnclaveResult<BTreeMap<String, Vec<String>>> {
        root_owned_not_writable(path)?;
        if let Some(d) = path.parent() {
            root_owned_not_writable(d)?;
        }
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        let file=std::fs::File::options().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC).open(path).map_err(|_|err!(EACCES,"CODESIGN_PINS_MISSING"))?;
        if !file.metadata().map_err(|_|err!(EACCES,"CODESIGN_PINS_INVALID"))?.is_file(){fail!(EACCES,"CODESIGN_PINS_INVALID");}
        let mut raw=Vec::new();file.take(1024*1024+1).read_to_end(&mut raw).map_err(|_|err!(EACCES,"CODESIGN_PINS_INVALID"))?;
        parse(&raw)
    }
    /// Bounded pure manifest parser, shared by fresh production loads and inert
    /// negative fixtures. Parsing alone does not establish trusted provenance.
    pub fn parse(raw:&[u8])->EnclaveResult<BTreeMap<String,Vec<String>>>{
        if raw.len()>1024*1024{fail!(E2BIG,"CODESIGN_PINS_INVALID");}
        let f: PinFile = serde_json::from_slice(raw)
            .map_err(|e| err!(EINVAL, "CODESIGN_PINS_INVALID", "{e}"))?;
        if f.v != 1 {
            fail!(EINVAL, "CODESIGN_PINS_INVALID", "version {}", f.v);
        }
        for (id, hs) in &f.pins {
            if hs.is_empty()
                || hs
                    .iter()
                    .any(|h| h.len() != 40 || !h.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                fail!(
                    EINVAL,
                    "CODESIGN_PINS_INVALID",
                    "{id}: cdhashes must be 40 hex characters"
                );
            }
        }
        Ok(f.pins)
    }

    /// Start-time check in [`super::SigningMode::LocalPins`]: the pin file
    /// is present, trustworthy and pins `identifier` (this daemon). Without
    /// it no peer could ever authenticate, so the daemon refuses to start
    /// rather than serving a mesh that silently rejects everything.
    pub fn require(identifier: &str) -> EnclaveResult<()> {
        let pins = load_selected()?;
        if !pins.contains_key(identifier) {
            if crate::deployment::selected().is_some() {
                fail!(EACCES, "CODESIGN_PINS_MISSING");
            }
            fail!(
                EACCES,
                "CODESIGN_PINS_MISSING",
                "{identifier} is not pinned in {}",
                super::PIN_FILE
            );
        }
        Ok(())
    }

    static PINS: OnceLock<BTreeMap<String, Vec<String>>> = OnceLock::new();

    // The context is immutable before either reader runs. Preserve the legacy
    // loader/cache without a descriptor; configured pins require the full held
    // no-follow root-protected chain and never try the global file on failure.
    pub(super) fn load_selected() -> EnclaveResult<BTreeMap<String, Vec<String>>> {
        let path = crate::deployment::selected_pin_file();
        if crate::deployment::selected().is_some() {
            let raw = crate::deployment::read_protected_public(&path, 1024 * 1024)?;
            parse(&raw).map_err(|_| err!(EACCES, "CODESIGN_PINS_INVALID"))
        } else {
            load(&path)
        }
    }

    /// The pinned cdhashes of `identifier` from [`super::PIN_FILE`] (empty:
    /// nothing matches).
    pub fn pinned(identifier: &str) -> Vec<String> {
        // Freeze even when an earlier call already populated the cache.
        let _ = crate::deployment::selected_pin_file();
        PINS.get_or_init(|| load_selected().unwrap_or_default())
            .get(identifier)
            .cloned()
            .unwrap_or_default()
    }
}

/// Whether this platform can verify code identity.
pub const fn enforced() -> bool {
    cfg!(target_os = "macos")
}

/// Verified code identity of a peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeIdentity {
    /// Signing identifier (e.g. `com.enterprise.enclave.ifc`).
    pub identifier: String,
    /// Team ID of the leaf certificate.
    pub team_id: String,
    /// Code directory hash (`kSecCodeInfoUnique`), hex.
    pub cdhash: String,
}

/// What a peer's code must satisfy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRequirement {
    /// Required signing identifier.
    pub identifier: String,
    /// Required Team ID.
    pub team_id: String,
    /// Optional cdhash allowlist (hex). Empty means "any build signed with
    /// this identity"; non-empty pins exact builds (distributed by TUF).
    pub cdhash_allowlist: Vec<String>,
}

impl CodeRequirement {
    fn for_identifier(identifier: String) -> Self {
        // Team-ID requirements also freeze the context before construction;
        // late deployment selection must not change later boundary authority.
        let _ = crate::deployment::selected_pin_file();
        let cdhash_allowlist = if crate::deployment::selected().is_some() {
            pins::pinned(&identifier)
        } else {
            match signing_mode() {
                SigningMode::TeamId => vec![],
                SigningMode::LocalPins => pins::pinned(&identifier),
            }
        };
        Self {
            identifier,
            team_id: TEAM_ID.into(),
            cdhash_allowlist,
        }
    }
    /// Requirement for one of the five daemons.
    pub fn daemon(d: DaemonId) -> Self {
        Self::for_identifier(d.launchd_label())
    }
    /// Requirement for the independent restricted root APFS broker.
    pub fn apfs_broker() -> crate::error::EnclaveResult<Self> { Self::pinned_boundary("com.enterprise.enclave.apfs-broker") }
    /// Exact build pin in either enterprise TeamID or local development mode.
    /// Callers must require a nonempty provisioned pin before authentication.
    pub fn pinned_boundary(identifier: &str) -> crate::error::EnclaveResult<Self> {
        Self::pinned_from_manifest(identifier,&pins::load_selected()?)
    }
    /// Build a requirement from a separately authenticated validated manifest.
    /// Each call selects fresh hashes; no cached authorization is consulted.
    pub fn pinned_from_manifest(identifier:&str,manifest:&BTreeMap<String,Vec<String>>)->crate::error::EnclaveResult<Self>{
        let hashes=manifest.get(identifier).filter(|v|!v.is_empty()).cloned().ok_or_else(||crate::err!(EACCES,"CODESIGN_PINS_MISSING"))?;
        let mut requirement=Self::for_identifier(identifier.into());requirement.cdhash_allowlist=hashes;Ok(requirement)
    }
    /// Requirement for the operator CLI (also the root supervisor binary).
    pub fn ctl() -> Self {
        Self::for_identifier(CTL_IDENTIFIER.into())
    }
    /// Requirement for the `_enclaveintent` biometric prompt helper (GAP-14).
    pub fn intent() -> Self {
        Self::for_identifier(INTENT_IDENTIFIER.into())
    }
    /// Requirement for the separately provisioned client ingress executable.
    pub fn gateway() -> Self {
        Self::for_identifier(crate::daemon::GATEWAY_IDENTIFIER.into())
    }
    /// Requirement for the sandboxed CDP browser daemon (GAP-34).
    pub fn browser() -> Self {
        Self::for_identifier(BROWSER_IDENTIFIER.into())
    }
    /// Designated-requirement text for `SecRequirementCreateWithString`.
    /// Without a Team ID the requirement is the identifier plus the pinned
    /// cdhashes — and `never` when nothing is pinned (fail closed).
    pub fn requirement_text(&self) -> String {
        if crate::deployment::selected().is_some() && self.cdhash_allowlist.is_empty() {
            return "never".into();
        }
        if !self.team_id.is_empty() {
            return format!(
                "anchor apple generic and certificate leaf[subject.OU] = \"{}\" and identifier \"{}\"",
                self.team_id, self.identifier
            );
        }
        if self.cdhash_allowlist.is_empty() {
            return "never".into();
        }
        let hashes: Vec<String> = self
            .cdhash_allowlist
            .iter()
            .map(|h| format!("cdhash H\"{}\"", h.to_ascii_lowercase()))
            .collect();
        format!(
            "identifier \"{}\" and ({})",
            self.identifier,
            hashes.join(" or ")
        )
    }
    /// Whether an already-verified identity matches (identifier, team, cdhash pin).
    /// Without a Team ID an empty allowlist matches nothing (as `never`).
    pub fn matches(&self, id: &CodeIdentity) -> bool {
        if (self.team_id.is_empty() || crate::deployment::selected().is_some()) && self.cdhash_allowlist.is_empty() {
            return false;
        }
        id.identifier == self.identifier
            && id.team_id == self.team_id
            && (self.cdhash_allowlist.is_empty()
                || self
                    .cdhash_allowlist
                    .iter()
                    .any(|h| h.eq_ignore_ascii_case(&id.cdhash)))
    }
}

#[cfg(target_os = "macos")]
pub use darwin::verify_peer;

/// Non-macOS: no code identity is available.
#[cfg(not(target_os = "macos"))]
pub fn verify_peer(
    _audit_token: &[u32; 8],
    _req: &CodeRequirement,
) -> crate::error::EnclaveResult<CodeIdentity> {
    crate::fail!(EACCES, "CODE_IDENTITY_UNAVAILABLE")
}

#[cfg(target_os = "macos")]
mod darwin {
    //! Minimal Security.framework / CoreFoundation binding.
    #![allow(non_upper_case_globals, non_camel_case_types)]

    use std::ffi::c_void;
    use std::os::raw::c_char;

    use super::{CodeIdentity, CodeRequirement};
    use crate::error::EnclaveResult;
    use crate::{err, fail};

    type CFTypeRef = *const c_void;
    type CFStringRef = *const c_void;
    type CFDataRef = *const c_void;
    type CFDictionaryRef = *const c_void;
    type CFAllocatorRef = *const c_void;
    type SecCodeRef = *const c_void;
    type SecRequirementRef = *const c_void;
    type CFIndex = isize;
    type OSStatus = i32;
    type SecCSFlags = u32;
    type Boolean = u8;

    const kCFStringEncodingUTF8: u32 = 0x0800_0100;
    const kSecCSDefaultFlags: SecCSFlags = 0;
    const kSecCSSigningInformation: SecCSFlags = 1 << 1;

    #[repr(C)]
    struct CFDictionaryCallBacks {
        _opaque: [u8; 0],
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        static kCFTypeDictionaryKeyCallBacks: CFDictionaryCallBacks;
        static kCFTypeDictionaryValueCallBacks: CFDictionaryCallBacks;
        fn CFDataCreate(alloc: CFAllocatorRef, bytes: *const u8, len: CFIndex) -> CFDataRef;
        fn CFDataGetLength(d: CFDataRef) -> CFIndex;
        fn CFDataGetBytePtr(d: CFDataRef) -> *const u8;
        fn CFDictionaryCreate(
            alloc: CFAllocatorRef,
            keys: *const CFTypeRef,
            values: *const CFTypeRef,
            n: CFIndex,
            kcb: *const CFDictionaryCallBacks,
            vcb: *const CFDictionaryCallBacks,
        ) -> CFDictionaryRef;
        fn CFDictionaryGetValue(d: CFDictionaryRef, key: CFTypeRef) -> CFTypeRef;
        fn CFStringCreateWithBytes(
            alloc: CFAllocatorRef,
            bytes: *const u8,
            len: CFIndex,
            enc: u32,
            external: Boolean,
        ) -> CFStringRef;
        fn CFStringGetCString(s: CFStringRef, buf: *mut c_char, size: CFIndex, enc: u32)
            -> Boolean;
        fn CFGetTypeID(t: CFTypeRef) -> usize;
        fn CFStringGetTypeID() -> usize;
        fn CFDataGetTypeID() -> usize;
        fn CFRelease(t: CFTypeRef);
    }

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        static kSecGuestAttributeAudit: CFStringRef;
        static kSecCodeInfoIdentifier: CFStringRef;
        static kSecCodeInfoTeamIdentifier: CFStringRef;
        static kSecCodeInfoUnique: CFStringRef;
        fn SecCodeCopyGuestWithAttributes(
            host: SecCodeRef,
            attrs: CFDictionaryRef,
            flags: SecCSFlags,
            guest: *mut SecCodeRef,
        ) -> OSStatus;
        fn SecRequirementCreateWithString(
            text: CFStringRef,
            flags: SecCSFlags,
            req: *mut SecRequirementRef,
        ) -> OSStatus;
        fn SecCodeCheckValidity(
            code: SecCodeRef,
            flags: SecCSFlags,
            req: SecRequirementRef,
        ) -> OSStatus;
        fn SecCodeCopySigningInformation(
            code: SecCodeRef,
            flags: SecCSFlags,
            info: *mut CFDictionaryRef,
        ) -> OSStatus;
    }

    /// Releases a CF object on drop.
    struct Cf(CFTypeRef);
    impl Drop for Cf {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: we own one retain count of a non-null CF object.
                unsafe { CFRelease(self.0) }
            }
        }
    }

    fn cfstr(s: &str) -> Cf {
        // SAFETY: valid UTF-8 slice; the result is owned by the returned guard.
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

    fn get_string(dict: CFDictionaryRef, key: CFStringRef) -> Option<String> {
        // SAFETY: `dict` is a live dictionary; values follow the Get rule (not owned).
        unsafe {
            let v = CFDictionaryGetValue(dict, key);
            if v.is_null() || CFGetTypeID(v) != CFStringGetTypeID() {
                return None;
            }
            let mut buf = [0 as c_char; 256];
            if CFStringGetCString(
                v,
                buf.as_mut_ptr(),
                buf.len() as CFIndex,
                kCFStringEncodingUTF8,
            ) == 0
            {
                return None;
            }
            std::ffi::CStr::from_ptr(buf.as_ptr())
                .to_str()
                .ok()
                .map(str::to_owned)
        }
    }

    fn get_data_hex(dict: CFDictionaryRef, key: CFStringRef) -> Option<String> {
        // SAFETY: as above; the byte pointer is valid for `len` while `dict` lives.
        unsafe {
            let v = CFDictionaryGetValue(dict, key);
            if v.is_null() || CFGetTypeID(v) != CFDataGetTypeID() {
                return None;
            }
            let n = CFDataGetLength(v) as usize;
            Some(hex::encode(std::slice::from_raw_parts(
                CFDataGetBytePtr(v),
                n,
            )))
        }
    }

    /// Resolve the peer process behind `audit_token`, check it against `req`,
    /// and return its verified identity. Any failure is a refusal.
    pub fn verify_peer(
        audit_token: &[u32; 8],
        req: &CodeRequirement,
    ) -> EnclaveResult<CodeIdentity> {
        // SAFETY: every CF object created here is wrapped in `Cf` and released;
        // pointers passed to Security.framework are live for the call.
        unsafe {
            let tok: Vec<u8> = audit_token.iter().flat_map(|w| w.to_ne_bytes()).collect();
            let data = Cf(CFDataCreate(
                std::ptr::null(),
                tok.as_ptr(),
                tok.len() as CFIndex,
            ));
            let keys = [kSecGuestAttributeAudit];
            let vals = [data.0];
            let attrs = Cf(CFDictionaryCreate(
                std::ptr::null(),
                keys.as_ptr(),
                vals.as_ptr(),
                1,
                &kCFTypeDictionaryKeyCallBacks,
                &kCFTypeDictionaryValueCallBacks,
            ));
            let mut code: SecCodeRef = std::ptr::null();
            let st = SecCodeCopyGuestWithAttributes(
                std::ptr::null(),
                attrs.0,
                kSecCSDefaultFlags,
                &mut code,
            );
            if st != 0 || code.is_null() {
                fail!(
                    EACCES,
                    "PEER_CODE_UNRESOLVED",
                    "SecCodeCopyGuestWithAttributes = {st}"
                );
            }
            let code = Cf(code);
            let text = cfstr(&req.requirement_text());
            let mut r: SecRequirementRef = std::ptr::null();
            let st = SecRequirementCreateWithString(text.0, kSecCSDefaultFlags, &mut r);
            if st != 0 || r.is_null() {
                fail!(
                    EINVAL,
                    "PEER_REQUIREMENT_INVALID",
                    "SecRequirementCreateWithString = {st}"
                );
            }
            let r = Cf(r);
            let st = SecCodeCheckValidity(code.0, kSecCSDefaultFlags, r.0);
            if st != 0 {
                fail!(
                    EACCES,
                    "PEER_CODESIGN_REJECTED",
                    "{} (OSStatus {st})",
                    req.identifier
                );
            }
            let mut info: CFDictionaryRef = std::ptr::null();
            let st = SecCodeCopySigningInformation(code.0, kSecCSSigningInformation, &mut info);
            if st != 0 || info.is_null() {
                fail!(
                    EACCES,
                    "PEER_SIGNING_INFO",
                    "SecCodeCopySigningInformation = {st}"
                );
            }
            let info = Cf(info);
            let id = CodeIdentity {
                identifier: get_string(info.0, kSecCodeInfoIdentifier)
                    .ok_or_else(|| err!(EACCES, "PEER_SIGNING_INFO", "identifier"))?,
                team_id: get_string(info.0, kSecCodeInfoTeamIdentifier).unwrap_or_default(),
                cdhash: get_data_hex(info.0, kSecCodeInfoUnique)
                    .ok_or_else(|| err!(EACCES, "PEER_SIGNING_INFO", "cdhash"))?,
            };
            if !req.matches(&id) {
                fail!(
                    EACCES,
                    "PEER_CDHASH_REJECTED",
                    "{} {}",
                    id.identifier,
                    id.cdhash
                );
            }
            Ok(id)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEAM: &str = "ABC123XYZ0";

    fn id(ident: &str, cdhash: &str) -> CodeIdentity {
        CodeIdentity {
            identifier: ident.into(),
            team_id: TEAM.into(),
            cdhash: cdhash.into(),
        }
    }

    #[test]
    fn unpinned_local_requirement_matches_nothing() {
        let r = CodeRequirement {
            identifier: "com.enterprise.enclave.ifc".into(),
            team_id: String::new(),
            cdhash_allowlist: vec![],
        };
        assert_eq!(r.requirement_text(), "never");
        assert!(!r.matches(&CodeIdentity {
            identifier: "com.enterprise.enclave.ifc".into(),
            team_id: String::new(),
            cdhash: "aa".repeat(20)
        }));
        assert_eq!(signing_mode() == SigningMode::LocalPins, TEAM_ID.is_empty());
    }

    #[test]
    fn requirement_text_and_matching() {
        let r = CodeRequirement {
            identifier: "com.enterprise.enclave.ifc".into(),
            team_id: TEAM.into(),
            cdhash_allowlist: vec![],
        };
        assert_eq!(r.requirement_text(), format!("anchor apple generic and certificate leaf[subject.OU] = \"{TEAM}\" and identifier \"com.enterprise.enclave.ifc\""));
        assert!(r.matches(&id("com.enterprise.enclave.ifc", "aa")));
        assert!(!r.matches(&id("com.enterprise.enclave.adapter", "aa")));
        let mut other_team = id("com.enterprise.enclave.ifc", "aa");
        other_team.team_id = "EVIL000000".into();
        assert!(!r.matches(&other_team));
        let pinned = CodeRequirement {
            cdhash_allowlist: vec!["AbCd".into()],
            ..r
        };
        assert!(pinned.matches(&id("com.enterprise.enclave.ifc", "abcd")));
        assert!(!pinned.matches(&id("com.enterprise.enclave.ifc", "abce")));
    }

    #[test]
    fn local_pins_requirement_text() {
        let r = CodeRequirement {
            identifier: "com.enterprise.enclave.cas".into(),
            team_id: String::new(),
            cdhash_allowlist: vec!["AB".repeat(20), "cd".repeat(20)],
        };
        assert_eq!(
            r.requirement_text(),
            format!(
                "identifier \"com.enterprise.enclave.cas\" and (cdhash H\"{}\" or cdhash H\"{}\")",
                "ab".repeat(20),
                "cd".repeat(20)
            )
        );
        assert!(r.matches(&CodeIdentity {
            identifier: "com.enterprise.enclave.cas".into(),
            team_id: String::new(),
            cdhash: "cd".repeat(20)
        }));
        assert!(!r.matches(&CodeIdentity {
            identifier: "com.enterprise.enclave.cas".into(),
            team_id: String::new(),
            cdhash: "ef".repeat(20)
        }));
    }

    #[test]
    fn pin_file_must_be_root_owned_and_well_formed() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = std::env::temp_dir().join(format!("depot-pins-{}", crate::rng::u64()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        let f = d.join("codesign-pins.json");
        let good = format!(
            "{{\"v\":1,\"pins\":{{\"com.enterprise.enclave.cas\":[\"{}\"]}}}}",
            "ab".repeat(20)
        );
        std::fs::write(&f, &good).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        if crate::ipc::geteuid() == 0 {
            assert_eq!(
                pins::load(&f).unwrap()["com.enterprise.enclave.cas"],
                vec!["ab".repeat(20)]
            );
            // Group-writable is refused.
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o664)).unwrap();
            assert!(pins::load(&f).unwrap_err().is("CODESIGN_PINS_INSECURE"));
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
            // Malformed cdhashes are refused.
            std::fs::write(&f, "{\"v\":1,\"pins\":{\"x\":[\"zz\"]}}").unwrap();
            assert!(pins::load(&f).unwrap_err().is("CODESIGN_PINS_INVALID"));
            // Not root-owned is refused.
            std::fs::write(&f, &good).unwrap();
            std::os::unix::fs::chown(&f, Some(4242), None).unwrap();
            if std::fs::symlink_metadata(&f).unwrap().uid() == 4242 {
                assert!(pins::load(&f).unwrap_err().is("CODESIGN_PINS_INSECURE"));
            } else {
                eprintln!("UNKNOWN_CODESIGN_WRONG_OWNER: filesystem did not apply distinct chown");
            }
        } else {
            assert!(
                pins::load(&f).unwrap_err().is("CODESIGN_PINS_INSECURE"),
                "a non-root-owned pin file is never trusted"
            );
        }
        assert!(pins::load(&d.join("absent.json"))
            .unwrap_err()
            .is("CODESIGN_PINS_MISSING"));
        let _ = std::fs::remove_dir_all(d);
    }
}
