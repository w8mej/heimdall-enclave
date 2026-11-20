//! Erasure of Rust heap allocations released by the proving executables.
//!
//! Plonky3 owns ordinary vectors containing private masks and witness-derived
//! intermediates. The two executable entry points install this allocator so
//! those buffers are erased before returning their storage to the system.
//! This does not erase live allocations, stack/register copies, foreign
//! framework allocations, or memory left behind by abort/forced termination.

use std::alloc::{GlobalAlloc, Layout, System};
use std::ptr;
use std::sync::atomic::{compiler_fence, Ordering};

/// An allocator that wipes every released allocation, including reallocations.
///
/// Library embedders that prove in-process must install an equivalent global
/// allocator themselves. `realloc` allocates before copying, preserving the old
/// allocation unchanged if allocation fails; its temporary peak includes both
/// buffers. No secret data is passed to the backing allocator after wiping.
#[derive(Debug)]
pub struct WipingAllocator<A = System>(pub A);

// SAFETY: allocation/layout validity and thread safety are inherited from A.
// Every successful allocation is returned with the requested size/alignment.
// Wipes access only the currently live allocation described by the caller.
unsafe impl<A: GlobalAlloc> GlobalAlloc for WipingAllocator<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller supplies a valid nonzero layout.
        unsafe { self.0.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller supplies a valid nonzero layout.
        unsafe { self.0.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the allocator contract guarantees this entire allocation is
        // live and exclusively owned, including previously uninitialized bytes.
        // Raw writes also cover uninitialized capacity without creating a
        // reference to uninitialized u8 values. Volatile writes and the compiler
        // fence prevent dead-store elimination. This never allocates or panics.
        for offset in 0..layout.size() {
            unsafe { ptr::write_volatile(ptr.add(offset), 0) };
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: wiping does not change pointer or allocation layout.
        unsafe { self.0.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, old: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: GlobalAlloc::realloc requires new_size > 0 and a layout with
        // this alignment/size that fits isize::MAX after rounding.
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        // SAFETY: new_layout satisfies alloc's contract above.
        let new = unsafe { self.0.alloc(new_layout) };
        if !new.is_null() {
            // SAFETY: both allocations are live and disjoint; the smaller size
            // lies within both. Copying MaybeUninit bytes via u8 pointers is OK.
            unsafe { ptr::copy_nonoverlapping(old, new, layout.size().min(new_size)) };
            // SAFETY: old is still live; only after copying may it be erased.
            unsafe { self.dealloc(old, layout) };
        }
        new
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct Observed {
        nonzero_at_free: AtomicBool,
        releases: AtomicUsize,
        fail: AtomicBool,
    }

    // Inspect bytes while still allocated, immediately before System frees
    // them. Reading after deallocation would be undefined and proves nothing.
    unsafe impl GlobalAlloc for Observed {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if self.fail.load(Ordering::SeqCst) { return ptr::null_mut(); }
            unsafe { System.alloc(layout) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            let dirty = unsafe { std::slice::from_raw_parts(ptr, layout.size()) }
                .iter().any(|b| *b != 0);
            self.nonzero_at_free.fetch_or(dirty, Ordering::SeqCst);
            self.releases.fetch_add(1, Ordering::SeqCst);
            unsafe { System.dealloc(ptr, layout) };
        }
    }

    fn allocator() -> WipingAllocator<Observed> {
        WipingAllocator(Observed {
            nonzero_at_free: AtomicBool::new(false),
            releases: AtomicUsize::new(0),
            fail: AtomicBool::new(false),
        })
    }

    #[test]
    fn phase5_heap_grow_shrink_and_free_erase_full_old_allocation() {
        let a = allocator();
        unsafe {
            let l = Layout::from_size_align(257, 64).unwrap();
            let p = a.alloc(l);
            assert!(!p.is_null());
            ptr::write_bytes(p, 0xA7, l.size());
            let q = a.realloc(p, l, 1025);
            assert!(!q.is_null());
            assert_eq!(q as usize % 64, 0);
            assert!(std::slice::from_raw_parts(q, 257).iter().all(|b| *b == 0xA7));
            ptr::write_bytes(q, 0xB8, 1025);
            let r = a.realloc(q, Layout::from_size_align(1025, 64).unwrap(), 17);
            assert!(!r.is_null());
            assert!(std::slice::from_raw_parts(r, 17).iter().all(|b| *b == 0xB8));
            a.dealloc(r, Layout::from_size_align(17, 64).unwrap());
        }
        assert_eq!(a.0.releases.load(Ordering::SeqCst), 3);
        assert!(!a.0.nonzero_at_free.load(Ordering::SeqCst));
    }

    #[test]
    fn phase5_heap_failed_realloc_keeps_original_live_and_unchanged() {
        let a = allocator();
        unsafe {
            let l = Layout::from_size_align(64, 16).unwrap();
            let p = a.alloc(l);
            assert!(!p.is_null());
            ptr::write_bytes(p, 0xC9, l.size());
            a.0.fail.store(true, Ordering::SeqCst);
            assert!(a.realloc(p, l, 128).is_null());
            assert_eq!(a.0.releases.load(Ordering::SeqCst), 0);
            assert!(std::slice::from_raw_parts(p, 64).iter().all(|b| *b == 0xC9));
            a.dealloc(p, l);
        }
        assert_eq!(a.0.releases.load(Ordering::SeqCst), 1);
        assert!(!a.0.nonzero_at_free.load(Ordering::SeqCst));
    }
}
