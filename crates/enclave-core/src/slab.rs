//! FS-705 §3.1 `SecureSlabAllocator`.
//!
//! * **Root keys** (`<= 32` per daemon): each gets a dedicated 1-object data
//!   page bracketed by `PROT_NONE` guard pages and is **right-aligned**, so the
//!   first byte past the key lies on the trailing guard page and traps.
//! * **Handles / control structs**: type-segregated 16 KiB slabs; every slot is
//!   framed by randomized per-object cookies (`BLAKE3_keyed(slab_secret,
//!   slot ‖ generation)`) checked on free and on scrub, so intra-slab
//!   overflows are detected at free/scrub time (F-018).
//! * Free = immediate volatile zeroing; slab drop = scrub + unmap.
//! * Silicon mode: `M5+` hardware tagging is used **only** after the
//!   `M5 Entitlement Verification Gate` records a citation; until then every
//!   host reports `PAC_GUARDED` (FS-705 §3.1, ADR-011).

use std::collections::HashMap;

use crate::error::EnclaveResult;
use crate::guarded::GuardedRegion;
use crate::secret::SecretKey32;
use crate::{err, fail};
use serde::{Deserialize, Serialize};

/// Maximum root-key pages per daemon.
pub const MAX_ROOT_KEYS: usize = 32;
/// Slab size.
pub const SLAB_BYTES: usize = 16 * 1024;
const COOKIE: usize = 8;

/// Memory-safety mode in effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SiliconMemoryMode {
    /// `M1`–`M4` (and `M5+` until the gate passes): PAC + guard pages + cookies.
    PacGuarded,
    /// `M5+` synchronous `EMTE` (requires the verified entitlement gate).
    EmteSync,
}

/// The `M5` Entitlement Verification Gate: the `sysctl` selector and
/// entitlement keys must be confirmed against Apple documentation and cited
/// (FS-705 §9) before `EMTE` behaviour is enabled.
#[derive(Debug, Clone, Default)]
pub struct EmteGate {
    /// Citation of the verified Apple documentation (none recorded yet).
    pub citation: Option<String>,
}

/// `[Unverified]` placeholder selector named by FS-705 §3.1.
pub const MTE4_SYSCTL_UNVERIFIED: &str = "hw.optional.arm.FEAT_MTE4";

/// Query a boolean `sysctl` (macOS); `None` if absent / unsupported.
pub fn sysctl_flag(name: &str) -> Option<bool> {
    #[cfg(target_os = "macos")]
    {
        let c = std::ffi::CString::new(name).ok()?;
        let mut v: i32 = 0;
        let mut len = std::mem::size_of::<i32>();
        // SAFETY: valid NUL-terminated name and correctly sized out-buffer.
        let rc = unsafe {
            libc::sysctlbyname(
                c.as_ptr(),
                (&mut v as *mut i32).cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        (rc == 0).then_some(v != 0)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = name;
        None
    }
}

/// Decide the silicon mode. Hardware support alone is **not** sufficient.
pub fn detect_mode(gate: &EmteGate) -> SiliconMemoryMode {
    match (sysctl_flag(MTE4_SYSCTL_UNVERIFIED), &gate.citation) {
        (Some(true), Some(_)) => SiliconMemoryMode::EmteSync,
        _ => SiliconMemoryMode::PacGuarded,
    }
}

/// A right-aligned root key on its own guarded page.
#[derive(Debug)]
pub struct RootKeyPage {
    region: GuardedRegion,
    len: usize,
}

impl RootKeyPage {
    /// Key bytes.
    pub fn expose(&self) -> EnclaveResult<&[u8]> {
        let s = self.region.as_slice()?;
        Ok(&s[s.len() - self.len..])
    }
    /// Address of the key's first byte (tests).
    pub fn key_addr(&self) -> usize {
        self.region.trailing_guard_addr() - self.len
    }
    /// Address of the first byte after the key (lies on the guard page).
    pub fn one_past_end(&self) -> usize {
        self.region.trailing_guard_addr()
    }
    /// Underlying region (registered with the panic zeroizer).
    pub fn region(&self) -> &GuardedRegion {
        &self.region
    }
}

/// Opaque slot handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SlotHandle {
    type_tag: u32,
    slab: usize,
    slot: usize,
    generation: u64,
}

struct Slab {
    region: GuardedRegion,
    slot_size: usize,
    used: Vec<Option<u64>>,
}

/// The allocator.
pub struct SecureSlabAllocator {
    secret: SecretKey32,
    roots: usize,
    slabs: HashMap<u32, (usize, Vec<Slab>)>,
    generation: u64,
    /// Mode in effect.
    pub mode: SiliconMemoryMode,
}

impl std::fmt::Debug for SecureSlabAllocator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureSlabAllocator")
            .field("roots", &self.roots)
            .field("types", &self.slabs.len())
            .field("mode", &self.mode)
            .finish()
    }
}

/// A detected memory-safety violation (feeds the quarantine strike policy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieFault {
    /// Type tag.
    pub type_tag: u32,
    /// Slot.
    pub slot: usize,
}

impl SecureSlabAllocator {
    /// New allocator.
    pub fn new(gate: &EmteGate) -> Self {
        Self {
            secret: SecretKey32::random(),
            roots: 0,
            slabs: HashMap::new(),
            generation: 0,
            mode: detect_mode(gate),
        }
    }

    /// Allocate a root key page holding `key` (copied in, right-aligned).
    pub fn alloc_root_key(&mut self, key: &[u8]) -> EnclaveResult<RootKeyPage> {
        if self.roots >= MAX_ROOT_KEYS {
            fail!(
                ENOMEM,
                "ROOT_KEY_CAP_EXCEEDED",
                "<= {MAX_ROOT_KEYS} root keys per daemon"
            );
        }
        if key.is_empty() || key.len() > 4096 {
            fail!(EINVAL, "ROOT_KEY_SIZE");
        }
        let mut region = GuardedRegion::new(key.len())?;
        {
            let s = region.as_mut_slice()?;
            let off = s.len() - key.len();
            s[off..].copy_from_slice(key);
        }
        self.roots += 1;
        Ok(RootKeyPage {
            region,
            len: key.len(),
        })
    }

    fn cookie(
        &self,
        tag: u32,
        slab: usize,
        slot: usize,
        generation: u64,
        which: u8,
    ) -> [u8; COOKIE] {
        let mut m = [0u8; 25];
        m[..4].copy_from_slice(&tag.to_le_bytes());
        m[4..12].copy_from_slice(&(slab as u64).to_le_bytes());
        m[12..20].copy_from_slice(&(slot as u64).to_le_bytes());
        m[20..24].copy_from_slice(&(generation as u32).to_le_bytes());
        m[24] = which;
        let h = self.secret.mac(&m);
        let mut c = [0u8; COOKIE];
        c.copy_from_slice(&h[..COOKIE]);
        c
    }

    /// Allocate a slot of `size` bytes in the slab class for `type_tag`.
    pub fn alloc(&mut self, type_tag: u32, size: usize, init: &[u8]) -> EnclaveResult<SlotHandle> {
        if size == 0 || size + 2 * COOKIE > SLAB_BYTES || init.len() > size {
            fail!(EINVAL, "SLAB_OBJECT_SIZE");
        }
        let slot_size = size + 2 * COOKIE;
        self.generation += 1;
        let generation = self.generation;
        let entry = self
            .slabs
            .entry(type_tag)
            .or_insert_with(|| (slot_size, Vec::new()));
        if entry.0 != slot_size {
            fail!(
                EINVAL,
                "SLAB_TYPE_SIZE_MISMATCH",
                "type {type_tag} is segregated at a fixed object size"
            );
        }
        let mut found = None;
        for (si, s) in entry.1.iter().enumerate() {
            if let Some(i) = s.used.iter().position(Option::is_none) {
                found = Some((si, i));
                break;
            }
        }
        let (si, i) = match found {
            Some(x) => x,
            None => {
                let region = GuardedRegion::new(SLAB_BYTES)?;
                let n = region.len() / slot_size;
                entry.1.push(Slab {
                    region,
                    slot_size,
                    used: vec![None; n],
                });
                (entry.1.len() - 1, 0)
            }
        };
        let (c0, c1) = (
            self.cookie(type_tag, si, i, generation, 0),
            self.cookie(type_tag, si, i, generation, 1),
        );
        let entry = self
            .slabs
            .get_mut(&type_tag)
            .ok_or_else(|| err!(EIO, "SLAB_STATE"))?;
        let s = &mut entry.1[si];
        let base = i * s.slot_size;
        let buf = s.region.as_mut_slice()?;
        buf[base..base + COOKIE].copy_from_slice(&c0);
        buf[base + COOKIE..base + COOKIE + init.len()].copy_from_slice(init);
        buf[base + COOKIE + size..base + 2 * COOKIE + size].copy_from_slice(&c1);
        s.used[i] = Some(generation);
        Ok(SlotHandle {
            type_tag,
            slab: si,
            slot: i,
            generation,
        })
    }

    fn slot_mut(&mut self, h: &SlotHandle) -> EnclaveResult<(&mut [u8], usize)> {
        let entry = self
            .slabs
            .get_mut(&h.type_tag)
            .ok_or_else(|| err!(EACCES, "SLAB_BAD_HANDLE"))?;
        let s = entry
            .1
            .get_mut(h.slab)
            .ok_or_else(|| err!(EACCES, "SLAB_BAD_HANDLE"))?;
        if s.used.get(h.slot).copied().flatten() != Some(h.generation) {
            fail!(EACCES, "SLAB_USE_AFTER_FREE", "stale or forged handle");
        }
        let ss = s.slot_size;
        let base = h.slot * ss;
        Ok((
            &mut s.region.as_mut_slice()?[base..base + ss],
            ss - 2 * COOKIE,
        ))
    }

    /// Mutable object bytes (writes past `size` land on the trailing cookie).
    pub fn object_mut(&mut self, h: &SlotHandle) -> EnclaveResult<&mut [u8]> {
        let (b, _size) = self.slot_mut(h)?;
        let n = b.len();
        // Deliberately hand out the cookie-bracketed span so a buggy writer
        // that overruns corrupts the cookie (detected on free), not a neighbour.
        Ok(&mut b[COOKIE..n])
    }

    /// Free: verify both cookies, zero the slot. A corrupted cookie is a
    /// heap-integrity fault (quarantine strike), and the slot is still wiped.
    pub fn free(&mut self, h: SlotHandle) -> Result<(), CookieFault> {
        let (c0, c1) = (
            self.cookie(h.type_tag, h.slab, h.slot, h.generation, 0),
            self.cookie(h.type_tag, h.slab, h.slot, h.generation, 1),
        );
        let fault = CookieFault {
            type_tag: h.type_tag,
            slot: h.slot,
        };
        let ok = match self.slot_mut(&h) {
            Ok((b, size)) => {
                let good = crate::secret::ct_eq(&b[..COOKIE], &c0)
                    && crate::secret::ct_eq(&b[COOKIE + size..], &c1);
                for x in b.iter_mut() {
                    // SAFETY: `x` is a valid, aligned, exclusive reference.
                    unsafe { std::ptr::write_volatile(x, 0) };
                }
                good
            }
            Err(_) => false,
        };
        if let Some(e) = self.slabs.get_mut(&h.type_tag) {
            if let Some(s) = e.1.get_mut(h.slab) {
                if let Some(u) = s.used.get_mut(h.slot) {
                    *u = None;
                }
            }
        }
        if ok {
            Ok(())
        } else {
            Err(fault)
        }
    }

    /// Scrub-time integrity sweep of every live slot.
    pub fn scan(&mut self) -> Vec<CookieFault> {
        let mut faults = Vec::new();
        let mut live = Vec::new();
        for (tag, (_, slabs)) in &self.slabs {
            for (si, s) in slabs.iter().enumerate() {
                for (i, g) in s.used.iter().enumerate() {
                    if let Some(g) = g {
                        live.push(SlotHandle {
                            type_tag: *tag,
                            slab: si,
                            slot: i,
                            generation: *g,
                        });
                    }
                }
            }
        }
        for h in live {
            let (c0, c1) = (
                self.cookie(h.type_tag, h.slab, h.slot, h.generation, 0),
                self.cookie(h.type_tag, h.slab, h.slot, h.generation, 1),
            );
            if let Ok((b, size)) = self.slot_mut(&h) {
                if !(b[..COOKIE] == c0 && b[COOKIE + size..] == c1) {
                    faults.push(CookieFault {
                        type_tag: h.type_tag,
                        slot: h.slot,
                    });
                }
            }
        }
        faults
    }

    /// Root keys allocated.
    pub fn root_keys(&self) -> usize {
        self.roots
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_key_right_aligned_and_capped() {
        let mut a = SecureSlabAllocator::new(&EmteGate::default());
        let k = a.alloc_root_key(&[7u8; 32]).unwrap();
        assert_eq!(k.expose().unwrap(), &[7u8; 32]);
        assert_eq!(k.one_past_end(), k.key_addr() + 32);
        let mut keep = vec![k];
        for _ in 1..MAX_ROOT_KEYS {
            keep.push(a.alloc_root_key(&[1u8; 32]).unwrap());
        }
        assert!(a
            .alloc_root_key(&[1u8; 32])
            .unwrap_err()
            .is("ROOT_KEY_CAP_EXCEEDED"));
    }

    #[test]
    fn overflow_detected_by_cookie_on_free_and_scan() {
        let mut a = SecureSlabAllocator::new(&EmteGate::default());
        let h1 = a.alloc(1, 64, b"handle-1").unwrap();
        let h2 = a.alloc(1, 64, b"handle-2").unwrap();
        // Off-by-one overflow past the 64-byte object.
        a.object_mut(&h1).unwrap()[64] ^= 0xff;
        assert_eq!(a.scan().len(), 1);
        assert!(a.free(h1).is_err());
        assert!(a.free(h2).is_ok());
        // Use-after-free and double free are rejected.
        assert!(a.object_mut(&h1).unwrap_err().is("SLAB_USE_AFTER_FREE"));
        assert!(a.free(h2).is_err());
        // Type segregation: a different size for the same tag is refused.
        assert!(a.alloc(1, 128, b"").is_err());
    }

    #[test]
    fn emte_requires_verified_gate() {
        assert_eq!(
            detect_mode(&EmteGate::default()),
            SiliconMemoryMode::PacGuarded
        );
    }
}
