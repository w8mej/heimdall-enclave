//! Hardware Metal scratch arena (FS-701 §4.2.2 / §7.1):
//! Per-request `MTLHeap` with `MTLSharedEvent` fence, blit `fillBuffer(0)`,
//! `explicit_bzero`, memory barrier, and canary page readback verification.
//! Full-buffer residual verification. The <=1ms hardware target requires macOS
//! measurement; the portable fallback is a CPU buffer, never Metal evidence.

use enclave_core::error::EnclaveResult;
#[cfg(target_os = "macos")]
use enclave_core::fail;
use std::sync::atomic::{fence, Ordering};

use crate::arena::WipeReport;

#[cfg(target_os = "macos")]
extern "C" {
    fn metal_device_create() -> *mut libc::c_void;
    fn metal_device_destroy(dev: *mut libc::c_void);
    fn metal_heap_create(dev: *mut libc::c_void, size: libc::size_t) -> *mut libc::c_void;
    fn metal_heap_destroy(heap: *mut libc::c_void);
    fn metal_buffer_create(heap: *mut libc::c_void, size: libc::size_t) -> *mut libc::c_void;
    fn metal_buffer_contents(buf: *mut libc::c_void) -> *mut libc::c_void;
    fn metal_buffer_length(buf: *mut libc::c_void) -> libc::size_t;
    fn metal_buffer_destroy(buf: *mut libc::c_void);
    fn metal_queue_create(dev: *mut libc::c_void) -> *mut libc::c_void;
    fn metal_queue_destroy(queue: *mut libc::c_void);
    fn metal_shared_event_create(dev: *mut libc::c_void) -> *mut libc::c_void;
    fn metal_shared_event_destroy(event: *mut libc::c_void);
    fn metal_wipe_buffer(
        queue: *mut libc::c_void,
        event: *mut libc::c_void,
        buffer: *mut libc::c_void,
        canary_offset: libc::size_t,
        canary_len: libc::size_t,
        out_elapsed_us: *mut u64,
    ) -> u64;
}

/// A hardware Metal scratch arena.
#[derive(Debug)]
pub struct MetalArena {
    #[cfg(target_os = "macos")]
    device: *mut libc::c_void,
    #[cfg(target_os = "macos")]
    heap: *mut libc::c_void,
    #[cfg(target_os = "macos")]
    buffer: *mut libc::c_void,
    #[cfg(target_os = "macos")]
    queue: *mut libc::c_void,
    #[cfg(target_os = "macos")]
    event: *mut libc::c_void,
    len: usize,
    canary_offset: usize,
    canary_len: usize,
    #[cfg(not(target_os = "macos"))]
    // u128 guarantees sufficient alignment for typed float views.
    fallback: Vec<u128>,
}

// SAFETY: MetalArena owns its handles and operates on dedicated memory.
unsafe impl Send for MetalArena {}

impl MetalArena {
    /// Allocate a new Metal scratch arena of `len` bytes (16 KiB aligned).
    /// The final 16 KiB (or `canary_len` bytes) is designated as the canary page.
    pub fn new(len: usize) -> EnclaveResult<Self> {
        let page_size = 16384usize; // Apple Silicon 16 KiB pages
        let aligned_len = len
            .max(1)
            .checked_add(page_size - 1)
            .and_then(|n| n.checked_div(page_size))
            .and_then(|n| n.checked_mul(page_size))
            .ok_or_else(|| enclave_core::err!(E2BIG, "METAL_ARENA_SIZE"))?;
        let canary_len = page_size;
        let canary_offset = aligned_len;
        let capacity = aligned_len
            .checked_add(canary_len)
            .ok_or_else(|| enclave_core::err!(E2BIG, "METAL_ARENA_SIZE"))?;

        #[cfg(target_os = "macos")]
        {
            // SAFETY: FFI to arena_metal.m functions.
            unsafe {
                let device = metal_device_create();
                if device.is_null() {
                    fail!(EIO, "METAL_DEVICE_UNAVAILABLE");
                }
                let heap = metal_heap_create(device, capacity);
                if heap.is_null() {
                    metal_device_destroy(device);
                    fail!(ENOMEM, "METAL_HEAP_ALLOCATION_FAILED");
                }
                let buffer = metal_buffer_create(heap, capacity);
                if buffer.is_null() {
                    metal_heap_destroy(heap);
                    metal_device_destroy(device);
                    fail!(ENOMEM, "METAL_BUFFER_ALLOCATION_FAILED");
                }
                let queue = metal_queue_create(device);
                if queue.is_null() {
                    metal_buffer_destroy(buffer);
                    metal_heap_destroy(heap);
                    metal_device_destroy(device);
                    fail!(EIO, "METAL_QUEUE_FAILED");
                }
                let event = metal_shared_event_create(device);
                if event.is_null() {
                    metal_queue_destroy(queue);
                    metal_buffer_destroy(buffer);
                    metal_heap_destroy(heap);
                    metal_device_destroy(device);
                    fail!(EIO, "METAL_SHARED_EVENT_FAILED");
                }

                if metal_buffer_contents(buffer).is_null() || metal_buffer_length(buffer) < capacity
                {
                    metal_shared_event_destroy(event);
                    metal_queue_destroy(queue);
                    metal_buffer_destroy(buffer);
                    metal_heap_destroy(heap);
                    metal_device_destroy(device);
                    fail!(EIO, "METAL_CONTENTS_UNAVAILABLE");
                }
                let mut arena = Self {
                    device,
                    heap,
                    buffer,
                    queue,
                    event,
                    len: aligned_len,
                    canary_offset,
                    canary_len,
                };
                arena.arm_canary();
                Ok(arena)
            }
        }

        #[cfg(not(target_os = "macos"))]
        {
            let mut arena = Self {
                len: aligned_len,
                canary_offset,
                canary_len,
                fallback: vec![0u128; capacity / std::mem::size_of::<u128>()],
            };
            arena.arm_canary();
            Ok(arena)
        }
    }

    /// Arm the canary page with a known non-zero pattern.
    pub fn arm_canary(&mut self) {
        let canary_bytes = self.canary_slice_mut();
        for (i, b) in canary_bytes.iter_mut().enumerate() {
            *b = ((i & 0x7f) as u8) ^ 0xa5;
        }
        fence(Ordering::SeqCst);
    }

    /// Total usable buffer length.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Hardware buffer capacity.
    pub fn buffer_length(&self) -> usize {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: buffer pointer is valid.
            unsafe { metal_buffer_length(self.buffer) }
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.len
        }
    }

    /// Whether buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Usable bytes view.
    fn storage(&self) -> &[u8] {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: buffer contents pointer is valid for `len` bytes while `self` lives.
            unsafe {
                let ptr = metal_buffer_contents(self.buffer) as *const u8;
                if ptr.is_null() {
                    &[]
                } else {
                    std::slice::from_raw_parts(ptr, self.canary_offset + self.canary_len)
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            // SAFETY: initialized contiguous u128 storage, viewed as bytes.
            unsafe {
                std::slice::from_raw_parts(
                    self.fallback.as_ptr().cast::<u8>(),
                    self.fallback.len() * std::mem::size_of::<u128>(),
                )
            }
        }
    }

    /// Mutable bytes view.
    fn storage_mut(&mut self) -> &mut [u8] {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: buffer contents pointer is valid for `len` bytes while `self` lives.
            unsafe {
                let ptr = metal_buffer_contents(self.buffer) as *mut u8;
                if ptr.is_null() {
                    &mut []
                } else {
                    std::slice::from_raw_parts_mut(ptr, self.canary_offset + self.canary_len)
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            // SAFETY: exclusive initialized contiguous storage, viewed as bytes.
            unsafe {
                std::slice::from_raw_parts_mut(
                    self.fallback.as_mut_ptr().cast::<u8>(),
                    self.fallback.len() * std::mem::size_of::<u128>(),
                )
            }
        }
    }

    /// Usable bytes; the separate canary page is never exposed as scratch.
    pub fn bytes(&self) -> &[u8] {
        &self.storage()[..self.len]
    }

    /// Exclusively borrowed usable scratch bytes.
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        let len = self.len;
        &mut self.storage_mut()[..len]
    }

    /// Slice representing the canary page.
    pub fn canary_slice(&self) -> &[u8] {
        &self.storage()[self.canary_offset..self.canary_offset + self.canary_len]
    }

    /// Mutable slice representing the canary page.
    pub fn canary_slice_mut(&mut self) -> &mut [u8] {
        let off = self.canary_offset;
        let l = self.canary_len;
        &mut self.storage_mut()[off..off + l]
    }

    /// Float view.
    pub fn f32(&self) -> &[f32] {
        let b = self.bytes();
        // SAFETY: Metal storage and the u128 fallback are aligned for f32; all bits are valid.
        unsafe { std::slice::from_raw_parts(b.as_ptr().cast::<f32>(), b.len() / 4) }
    }

    /// Mutable float view.
    pub fn f32_mut(&mut self) -> &mut [f32] {
        let b = self.bytes_mut();
        let l = b.len() / 4;
        // SAFETY: aligned native/u128 storage with an exclusive borrow.
        unsafe { std::slice::from_raw_parts_mut(b.as_mut_ptr().cast::<f32>(), l) }
    }

    /// Hardware fence-synchronized wipe:
    /// waitUntilCompleted -> blit fillBuffer(0) -> explicit_bzero -> fence -> canary verify.
    pub fn wipe(&mut self) -> WipeReport {
        #[cfg(target_os = "macos")]
        {
            let mut elapsed_us = 0u64;
            // SAFETY: calling metal_wipe_buffer with valid owned pointers.
            let residual = unsafe {
                metal_wipe_buffer(
                    self.queue,
                    self.event,
                    self.buffer,
                    self.canary_offset,
                    self.canary_len,
                    &mut elapsed_us,
                )
            };
            WipeReport {
                bytes: (self.canary_offset + self.canary_len) as u64,
                residual,
                micros: elapsed_us,
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let t = std::time::Instant::now();
            for b in self.fallback.iter_mut() {
                unsafe { std::ptr::write_volatile(b, 0) };
            }
            fence(Ordering::SeqCst);
            let residual = self.storage().iter().filter(|&&b| b != 0).count() as u64;
            WipeReport {
                bytes: (self.canary_offset + self.canary_len) as u64,
                residual,
                micros: t.elapsed().as_micros() as u64,
            }
        }
    }

    /// Wipe; on any residual byte abort the process (`SIGABRT`, FS-701 §7.1).
    pub fn wipe_or_abort(&mut self) -> WipeReport {
        let r = self.wipe();
        if r.residual != 0 {
            std::process::abort();
        }
        r
    }
}

impl Drop for MetalArena {
    fn drop(&mut self) {
        self.wipe_or_abort();
        #[cfg(target_os = "macos")]
        unsafe {
            if !self.buffer.is_null() {
                metal_buffer_destroy(self.buffer);
            }
            if !self.queue.is_null() {
                metal_queue_destroy(self.queue);
            }
            if !self.event.is_null() {
                metal_shared_event_destroy(self.event);
            }
            if !self.heap.is_null() {
                metal_heap_destroy(self.heap);
            }
            if !self.device.is_null() {
                metal_device_destroy(self.device);
            }
        }
    }
}
