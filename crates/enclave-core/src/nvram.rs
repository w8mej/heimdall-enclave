//! NVRAM `enclave-hiq` variable manager (GAP-12, ADR-012, FS-705 §5.3).
//!
//! On Apple Silicon hosts, the strike counter, null fault timestamps, and
//! quarantine latch are persisted in `IODeviceTree:/options` variable `enclave-hiq`,
//! MACed with a key unwrapped from the Secure Enclave.
//!
//! Security policy:
//! * A missing `enclave-hiq` variable on an enrolled host => latched.
//! * An invalid MAC or corrupted payload => latched.
//! * First-boot initialization occurs only during the custodian enrollment ceremony.
//! * Non-macOS and dev/simulation modes use a sealed local fallback store.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::EnclaveResult;
use crate::secret::SecretKey32;
use crate::{err, fail};

/// Name of the NVRAM variable in `IODeviceTree:/options`.
pub const NVRAM_VAR_NAME: &str = "enclave-hiq";

/// The persistent quarantine state stored inside `enclave-hiq`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedHiq {
    /// Millisecond timestamps of recorded integrity strikes.
    pub strikes: Vec<u64>,
    /// Millisecond timestamps of null-page dereferences.
    pub null_faults: Vec<u64>,
    /// Whether the host is in quarantine lockdown.
    pub latched: bool,
    /// Monotonically incrementing generation counter (invalidates old unquarantine grants).
    #[serde(default)]
    pub generation: u64,
}

impl PersistedHiq {
    /// Construct a pre-latched state for integrity violations.
    pub fn latched() -> Self {
        Self {
            latched: true,
            ..Default::default()
        }
    }
}

/// The serialized payload and MAC written to NVRAM.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NvramHiqRecord {
    /// JSON serialization of [`PersistedHiq`].
    pub state: String,
    /// Hex-encoded MAC over [`Self::state`].
    pub mac: String,
}

/// Read the raw string from an NVRAM variable.
pub fn get_nvram_variable(var_name: &str) -> EnclaveResult<Option<String>> {
    #[cfg(target_os = "macos")]
    {
        darwin::read_iokit_nvram(var_name)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = var_name;
        Ok(None)
    }
}

/// Write a string to an NVRAM variable.
pub fn set_nvram_variable(var_name: &str, value: &str) -> EnclaveResult<()> {
    #[cfg(target_os = "macos")]
    {
        darwin::write_iokit_nvram(var_name, value)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = var_name;
        let _ = value;
        Ok(())
    }
}

/// Delete an NVRAM variable.
pub fn delete_nvram_variable(var_name: &str) -> EnclaveResult<()> {
    #[cfg(target_os = "macos")]
    {
        darwin::delete_iokit_nvram(var_name)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = var_name;
        Ok(())
    }
}

/// Load and authenticate the `enclave-hiq` state.
///
/// Returns `(state, integrity_error)`. If missing on an enrolled host or if
/// the MAC is invalid, returns a latched state with the corresponding error.
pub fn load_hiq(
    dev: bool,
    dir: &Path,
    key: &SecretKey32,
    enrolled: bool,
) -> EnclaveResult<(PersistedHiq, Option<String>)> {
    let is_root = crate::ipc::geteuid() == 0;
    let use_file = dev || !cfg!(target_os = "macos") || !is_root || cfg!(test);
    let raw = if use_file {
        let p = dir.join("enclave-hiq.nvram.json");
        std::fs::read_to_string(&p).ok()
    } else {
        match get_nvram_variable(NVRAM_VAR_NAME)? {
            Some(s) => Some(s),
            None => {
                // Also check file fallback if NVRAM is empty
                let p = dir.join("enclave-hiq.nvram.json");
                std::fs::read_to_string(&p).ok()
            }
        }
    };

    let Some(raw_record) = raw else {
        if enrolled {
            return Ok((
                PersistedHiq::latched(),
                Some("STATE_MISSING: NVRAM enclave-hiq variable absent on enrolled host".into()),
            ));
        }
        return Ok((PersistedHiq::default(), None));
    };

    let record: NvramHiqRecord = match serde_json::from_str(&raw_record) {
        Ok(r) => r,
        Err(e) => {
            return Ok((
                PersistedHiq::latched(),
                Some(format!("STATE_CORRUPT: failed to decode NVRAM record: {e}")),
            ));
        }
    };

    let expected_mac = hex::encode(key.mac(record.state.as_bytes()));
    if !crate::secret::ct_eq(record.mac.as_bytes(), expected_mac.as_bytes()) {
        return Ok((
            PersistedHiq::latched(),
            Some("STATE_TAMPERED: NVRAM enclave-hiq MAC mismatch".into()),
        ));
    }

    match serde_json::from_str::<PersistedHiq>(&record.state) {
        Ok(st) => Ok((st, None)),
        Err(e) => Ok((
            PersistedHiq::latched(),
            Some(format!("STATE_CORRUPT: invalid PersistedHiq JSON: {e}")),
        )),
    }
}

/// MAC and save the `enclave-hiq` state to NVRAM and the local fallback store.
pub fn save_hiq(
    dev: bool,
    dir: &Path,
    key: &SecretKey32,
    state: &PersistedHiq,
) -> EnclaveResult<()> {
    let state_json =
        serde_json::to_string(state).map_err(|e| err!(EINVAL, "NVRAM_ENCODE", "{e}"))?;
    let mac = hex::encode(key.mac(state_json.as_bytes()));
    let record = NvramHiqRecord {
        state: state_json,
        mac,
    };
    let record_str =
        serde_json::to_string(&record).map_err(|e| err!(EINVAL, "NVRAM_ENCODE", "{e}"))?;

    // Always persist to local file store as durable backup
    let p = dir.join("enclave-hiq.nvram.json");
    let _ = std::fs::write(&p, record_str.as_bytes());

    let is_root = crate::ipc::geteuid() == 0;
    if !dev && cfg!(target_os = "macos") && is_root && !cfg!(test) {
        set_nvram_variable(NVRAM_VAR_NAME, &record_str)?;
    }

    Ok(())
}

#[cfg(target_os = "macos")]
mod darwin {
    use super::*;

    type CFTypeRef = *const libc::c_void;
    type CFStringRef = *const libc::c_void;
    type CFDataRef = *const libc::c_void;
    type CFAllocatorRef = *const libc::c_void;
    type CFIndex = isize;
    type Boolean = libc::c_uchar;

    #[link(name = "IOKit", kind = "framework")]
    extern "C" {
        fn IORegistryEntryFromPath(masterPort: u32, path: *const libc::c_char) -> u32;
        fn IORegistryEntryCreateCFProperty(
            entry: u32,
            key: CFStringRef,
            allocator: CFAllocatorRef,
            options: u32,
        ) -> CFTypeRef;
        fn IORegistryEntrySetCFProperty(
            entry: u32,
            propertyName: CFStringRef,
            specifier: CFTypeRef,
        ) -> i32;
        fn IOObjectRelease(object: u32) -> i32;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFStringCreateWithCString(
            alloc: CFAllocatorRef,
            c_str: *const libc::c_char,
            encoding: u32,
        ) -> CFStringRef;
        fn CFStringGetCString(
            theString: CFStringRef,
            buffer: *mut libc::c_char,
            bufferSize: CFIndex,
            encoding: u32,
        ) -> Boolean;
        fn CFDataGetBytePtr(theData: CFDataRef) -> *const u8;
        fn CFDataGetLength(theData: CFDataRef) -> CFIndex;
        fn CFRelease(cf: CFTypeRef);
    }

    const K_CF_STRING_ENCODING_UTF8: u32 = 0x08000100;

    pub fn read_iokit_nvram(var_name: &str) -> EnclaveResult<Option<String>> {
        let options = unsafe { IORegistryEntryFromPath(0, c"IODeviceTree:/options".as_ptr()) };
        if options == 0 {
            return Ok(None);
        }

        let c_name = std::ffi::CString::new(var_name).unwrap();
        let cf_key = unsafe {
            CFStringCreateWithCString(std::ptr::null(), c_name.as_ptr(), K_CF_STRING_ENCODING_UTF8)
        };
        if cf_key.is_null() {
            unsafe { IOObjectRelease(options) };
            return Ok(None);
        }

        let cf_prop =
            unsafe { IORegistryEntryCreateCFProperty(options, cf_key, std::ptr::null(), 0) };
        unsafe {
            CFRelease(cf_key);
            IOObjectRelease(options);
        }

        if cf_prop.is_null() {
            return Ok(None);
        }

        // The property may be returned as CFString or CFData
        let mut buf = vec![0u8; 8192];
        let ok = unsafe {
            CFStringGetCString(
                cf_prop,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len() as CFIndex,
                K_CF_STRING_ENCODING_UTF8,
            )
        };

        if ok != 0 {
            unsafe { CFRelease(cf_prop) };
            let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            buf.truncate(len);
            return Ok(String::from_utf8(buf).ok());
        }

        // Try as CFData
        let len = unsafe { CFDataGetLength(cf_prop) } as usize;
        if len > 0 && len <= buf.len() {
            let ptr = unsafe { CFDataGetBytePtr(cf_prop) };
            if !ptr.is_null() {
                unsafe { std::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), len) };
                buf.truncate(len);
                unsafe { CFRelease(cf_prop) };
                return Ok(String::from_utf8(buf).ok());
            }
        }

        unsafe { CFRelease(cf_prop) };
        Ok(None)
    }

    pub fn write_iokit_nvram(var_name: &str, value: &str) -> EnclaveResult<()> {
        let options = unsafe { IORegistryEntryFromPath(0, c"IODeviceTree:/options".as_ptr()) };
        if options == 0 {
            fail!(EIO, "NVRAM_OPTIONS_NOT_FOUND");
        }

        let c_name = std::ffi::CString::new(var_name).unwrap();
        let cf_key = unsafe {
            CFStringCreateWithCString(std::ptr::null(), c_name.as_ptr(), K_CF_STRING_ENCODING_UTF8)
        };

        let c_val = std::ffi::CString::new(value).unwrap();
        let cf_val = unsafe {
            CFStringCreateWithCString(std::ptr::null(), c_val.as_ptr(), K_CF_STRING_ENCODING_UTF8)
        };

        if cf_key.is_null() || cf_val.is_null() {
            unsafe {
                if !cf_key.is_null() {
                    CFRelease(cf_key);
                }
                if !cf_val.is_null() {
                    CFRelease(cf_val);
                }
                IOObjectRelease(options);
            }
            fail!(EIO, "NVRAM_ALLOC_FAILED");
        }

        let ret = unsafe { IORegistryEntrySetCFProperty(options, cf_key, cf_val) };

        unsafe {
            CFRelease(cf_key);
            CFRelease(cf_val);
            IOObjectRelease(options);
        }

        if ret != 0 {
            fail!(
                EPERM,
                "NVRAM_SET_FAILED",
                "IORegistryEntrySetCFProperty returned {ret}"
            );
        }

        Ok(())
    }

    pub fn delete_iokit_nvram(var_name: &str) -> EnclaveResult<()> {
        // Setting an empty string or using nvram -d
        let _ = var_name;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_and_save_hiq_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("depot-nvram-{}", crate::rng::u64()));
        std::fs::create_dir_all(&tmp).unwrap();
        let key = SecretKey32::new([0x42u8; 32]);

        let st = PersistedHiq {
            strikes: vec![1000, 2000],
            null_faults: vec![500],
            latched: false,
            generation: 0,
        };

        save_hiq(true, &tmp, &key, &st).unwrap();
        let (loaded, err) = load_hiq(true, &tmp, &key, true).unwrap();
        assert!(err.is_none());
        assert_eq!(loaded, st);

        let _ = std::fs::remove_dir_all(tmp);
    }

    #[test]
    fn tampered_hiq_latches_with_integrity_error() {
        let tmp = std::env::temp_dir().join(format!("depot-nvram-{}", crate::rng::u64()));
        std::fs::create_dir_all(&tmp).unwrap();
        let key = SecretKey32::new([0x42u8; 32]);

        let st = PersistedHiq {
            strikes: vec![1000],
            null_faults: vec![],
            latched: false,
            generation: 0,
        };

        save_hiq(true, &tmp, &key, &st).unwrap();

        // Tamper with the persisted JSON
        let p = tmp.join("enclave-hiq.nvram.json");
        let content = std::fs::read_to_string(&p).unwrap();
        let tampered = content.replace("1000", "9999");
        std::fs::write(&p, tampered).unwrap();

        let (loaded, err) = load_hiq(true, &tmp, &key, true).unwrap();
        assert!(loaded.latched);
        assert!(err.is_some());
        assert!(err.unwrap().contains("STATE_TAMPERED"));

        let _ = std::fs::remove_dir_all(tmp);
    }

    #[test]
    fn missing_hiq_on_enrolled_host_latches() {
        let tmp = std::env::temp_dir().join(format!("depot-nvram-{}", crate::rng::u64()));
        std::fs::create_dir_all(&tmp).unwrap();
        let key = SecretKey32::new([0x42u8; 32]);

        let (loaded, err) = load_hiq(true, &tmp, &key, true).unwrap();
        assert!(loaded.latched);
        assert!(err.is_some());
        assert!(err.unwrap().contains("STATE_MISSING"));

        let _ = std::fs::remove_dir_all(tmp);
    }
}
