//! Page-granular guarded memory regions: `mmap` + `mlock` + `mprotect`.
//!
//! A [`GuardedRegion`] is `guard ‖ data ‖ guard` where both guards are
//! `PROT_NONE`, so linear overflow/underflow faults on the first byte past
//! the data pages. [`GuardedRegion::freeze`] flips the data pages to
//! `PROT_NONE` (the `< 0.5 ms` "Lock" phase of Lock-Then-Scrub, FS-703 §5.2);
//! [`GuardedRegion::scrub`] makes them writable just long enough to zero them
//! with volatile writes and re-protects them. This is the substrate of the
//! FS-705 `SecureSlabAllocator` root-key pages and the UID 703 panic zeroizer.

use std::ptr::NonNull;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::error::EnclaveResult;
use crate::{err, fail};

/// System page size (16 KiB on Apple Silicon, 4 KiB on most x86-64 Linux).
pub fn page_size() -> usize {
    // SAFETY: sysconf has no preconditions.
    let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if p <= 0 {
        16 * 1024
    } else {
        p as usize
    }
}

const ST_RW: u8 = 0;
const ST_FROZEN: u8 = 1;
const ST_SCRUBBED: u8 = 2;
const ST_RO: u8 = 3;
const ST_FROZEN_RO: u8 = 4;

/// A guarded, locked, page-aligned region.
#[derive(Debug)]
pub struct GuardedRegion {
    base: NonNull<u8>,
    total: usize,
    data_len: usize,
    page: usize,
    state: AtomicU8,
    locked: bool,
}

// SAFETY: the region is a private anonymous mapping owned exclusively by this
// struct; all mutation goes through &mut self or atomic protection changes.
unsafe impl Send for GuardedRegion {}
// SAFETY: shared access only performs mprotect / volatile zeroing, which are
// safe to race with each other (protection changes are atomic at the kernel).
unsafe impl Sync for GuardedRegion {}

impl GuardedRegion {
    /// Map `len` usable bytes (rounded up to whole pages) between two guard pages.
    pub fn new(len: usize) -> EnclaveResult<Self> {
        if len == 0 {
            fail!(EINVAL, "GUARDED_ZERO_LEN");
        }
        let page = page_size();
        let data_pages = len.div_ceil(page);
        let total = (data_pages + 2) * page;
        // SAFETY: anonymous private mapping with no file descriptor.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                total,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            fail!(ENOMEM, "GUARDED_MMAP");
        }
        let base = NonNull::new(p.cast::<u8>()).ok_or_else(|| err!(ENOMEM, "GUARDED_MMAP"))?;
        let data = data_pages * page;
        // SAFETY: [base+page, base+page+data) lies inside the mapping.
        let rc = unsafe {
            libc::mprotect(
                base.as_ptr().add(page).cast(),
                data,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        };
        if rc != 0 {
            // SAFETY: unmapping exactly what we mapped.
            unsafe { libc::munmap(p, total) };
            fail!(ENOMEM, "GUARDED_MPROTECT");
        }
        // SAFETY: same data range; mlock only affects residency.
        let locked = unsafe { libc::mlock(base.as_ptr().add(page).cast(), data) } == 0;
        Ok(Self {
            base,
            total,
            data_len: data,
            page,
            state: AtomicU8::new(ST_RW),
            locked,
        })
    }

    /// Usable length (whole pages).
    pub fn len(&self) -> usize {
        self.data_len
    }
    /// Always false (regions are never empty).
    pub fn is_empty(&self) -> bool {
        false
    }
    /// Whether `mlock` succeeded.
    pub fn is_locked(&self) -> bool {
        self.locked
    }
    /// Data start pointer.
    pub fn data_ptr(&self) -> *mut u8 {
        // SAFETY: page offset is within the mapping.
        unsafe { self.base.as_ptr().add(self.page) }
    }
    /// Address of the first byte of the trailing guard page.
    pub fn trailing_guard_addr(&self) -> usize {
        self.data_ptr() as usize + self.data_len
    }

    /// Mutable view. Fails if frozen or scrubbed.
    pub fn as_mut_slice(&mut self) -> EnclaveResult<&mut [u8]> {
        if self.state.load(Ordering::SeqCst) != ST_RW {
            fail!(EACCES, "GUARDED_REGION_FROZEN");
        }
        // SAFETY: data pages are RW while state == RW and we hold &mut self.
        Ok(unsafe { std::slice::from_raw_parts_mut(self.data_ptr(), self.data_len) })
    }
    /// Shared view. Fails if frozen or scrubbed (read-only regions are readable).
    pub fn as_slice(&self) -> EnclaveResult<&[u8]> {
        let st = self.state.load(Ordering::SeqCst);
        if st != ST_RW && st != ST_RO {
            fail!(EACCES, "GUARDED_REGION_FROZEN");
        }
        // SAFETY: data pages are readable while state == RW.
        Ok(unsafe { std::slice::from_raw_parts(self.data_ptr(), self.data_len) })
    }

    fn protect(&self, prot: libc::c_int) -> bool {
        // SAFETY: data range inside the mapping.
        unsafe { libc::mprotect(self.data_ptr().cast(), self.data_len, prot) == 0 }
    }

    /// Seal the data pages hardware read-only (`PROT_READ`): used for clean
    /// system states such as the FS-701 `h_sys` snapshot. Irreversible except
    /// through [`GuardedRegion::scrub`].
    pub fn seal_read_only(&self) -> EnclaveResult<()> {
        if self.state.load(Ordering::SeqCst) != ST_RW {
            fail!(EACCES, "GUARDED_REGION_FROZEN");
        }
        if !self.protect(libc::PROT_READ) {
            fail!(EIO, "GUARDED_MPROTECT");
        }
        self.state.store(ST_RO, Ordering::SeqCst);
        Ok(())
    }

    /// Whether sealed read-only.
    pub fn is_read_only(&self) -> bool {
        self.state.load(Ordering::SeqCst) == ST_RO
    }

    /// Phase 1: CPU page-table freeze (`PROT_NONE`). Idempotent.
    pub fn freeze(&self) -> bool {
        let ok = self.protect(libc::PROT_NONE);
        if ok {
            let _ =
                self.state
                    .compare_exchange(ST_RW, ST_FROZEN, Ordering::SeqCst, Ordering::SeqCst);
            let _ = self.state.compare_exchange(
                ST_RO,
                ST_FROZEN_RO,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
        }
        ok
    }

    /// Re-attest succeeded: thaw a frozen (not scrubbed) region.
    pub fn thaw(&self) -> EnclaveResult<()> {
        let (prot, back) = match self.state.load(Ordering::SeqCst) {
            ST_FROZEN => (libc::PROT_READ | libc::PROT_WRITE, ST_RW),
            ST_FROZEN_RO => (libc::PROT_READ, ST_RO),
            _ => fail!(EACCES, "GUARDED_NOT_FROZEN"),
        };
        if !self.protect(prot) {
            fail!(EIO, "GUARDED_MPROTECT");
        }
        self.state.store(back, Ordering::SeqCst);
        Ok(())
    }

    /// Phase 2: zeroize (volatile) and leave `PROT_NONE`. Irreversible.
    pub fn scrub(&self) -> bool {
        if !self.protect(libc::PROT_READ | libc::PROT_WRITE) {
            return false;
        }
        let p = self.data_ptr();
        for i in 0..self.data_len {
            // SAFETY: in-bounds, writable for the duration of the scrub.
            unsafe { std::ptr::write_volatile(p.add(i), 0) };
        }
        std::sync::atomic::compiler_fence(Ordering::SeqCst);
        self.state.store(ST_SCRUBBED, Ordering::SeqCst);
        self.protect(libc::PROT_NONE)
    }

    /// Whether scrubbed.
    pub fn is_scrubbed(&self) -> bool {
        self.state.load(Ordering::SeqCst) == ST_SCRUBBED
    }
    /// Whether frozen.
    pub fn is_frozen(&self) -> bool {
        matches!(self.state.load(Ordering::SeqCst), ST_FROZEN | ST_FROZEN_RO)
    }

    /// Test helper: verify every byte is zero (temporarily readable).
    pub fn verify_zeroed(&self) -> bool {
        if !self.protect(libc::PROT_READ) {
            return false;
        }
        // SAFETY: readable for the duration of the check.
        let z = unsafe { std::slice::from_raw_parts(self.data_ptr(), self.data_len) }
            .iter()
            .all(|b| *b == 0);
        self.protect(libc::PROT_NONE);
        z
    }
}

impl Drop for GuardedRegion {
    fn drop(&mut self) {
        self.scrub();
        // SAFETY: unmapping exactly the original mapping.
        unsafe {
            if self.locked {
                libc::munlock(self.data_ptr().cast(), self.data_len);
            }
            libc::munmap(self.base.as_ptr().cast(), self.total);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_seal_survives_freeze_thaw() {
        let mut r = GuardedRegion::new(100).unwrap();
        r.as_mut_slice().unwrap()[0] = 7;
        r.seal_read_only().unwrap();
        assert!(r.as_mut_slice().is_err());
        assert_eq!(r.as_slice().unwrap()[0], 7);
        assert!(r.freeze());
        assert!(r.as_slice().is_err());
        r.thaw().unwrap();
        assert!(r.is_read_only() && r.as_mut_slice().is_err());
        assert!(r.scrub() && r.verify_zeroed());
    }

    #[test]
    fn write_freeze_thaw_scrub() {
        let mut r = GuardedRegion::new(100).unwrap();
        r.as_mut_slice().unwrap()[..5].copy_from_slice(b"hello");
        assert!(r.freeze());
        assert!(r.as_slice().is_err());
        r.thaw().unwrap();
        assert_eq!(&r.as_slice().unwrap()[..5], b"hello");
        assert!(r.scrub());
        assert!(r.is_scrubbed());
        assert!(r.verify_zeroed());
        assert!(r.thaw().is_err(), "scrub is irreversible");
        assert_eq!(r.len() % page_size(), 0);
    }
}
