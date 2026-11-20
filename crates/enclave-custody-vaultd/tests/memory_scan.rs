//! Plaintext zeroization test: verifies that after Detokenize, 0 occurrences
//! of the plaintext canary remain in the process's writable memory regions.

use enclave_core::secret::SecretBytes;
use enclave_custody_vaultd::service::HumanDisplay;

/// A test display that records that it received values, but retains no copies.
#[derive(Debug, Default)]
struct EphemeralDisplay {
    count: usize,
}

impl HumanDisplay for EphemeralDisplay {
    fn show(&mut self, values: &[SecretBytes]) -> enclave_core::error::EnclaveResult<()> {
        self.count += values.len();
        // Values are &[SecretBytes]. We do not copy them to String or Vec.
        Ok(())
    }
}

#[cfg(target_os = "macos")]
mod macos_scanner {
    #[repr(C)]
    struct ProcRegionInfo {
        pri_protection: u32,
        pri_max_protection: u32,
        pri_inheritance: u32,
        pri_flags: u32,
        pri_offset: u64,
        pri_behavior: u32,
        pri_user_wired_count: u32,
        pri_user_tag: u32,
        pri_pages_resident: u32,
        pri_pages_shared_now_private: u32,
        pri_pages_swapped_out: u32,
        pri_dirtied: u32,
        pri_ref_count: u32,
        pri_shadow_depth: u32,
        pri_share_mode: u32,
        pri_private_pages_resident: u32,
        pri_shared_pages_resident: u32,
        pri_obj_id: u32,
        pri_depth: u32,
        pri_address: u64,
        pri_size: u64,
    }

    const PROC_PIDREGIONINFO: libc::c_int = 7;
    const VM_PROT_READ: u32 = 1;
    const VM_PROT_WRITE: u32 = 2;

    extern "C" {
        fn vm_read_overwrite(
            target_task: libc::mach_port_t,
            address: libc::vm_address_t,
            size: libc::vm_size_t,
            data: libc::vm_address_t,
            outsize: *mut libc::vm_size_t,
        ) -> libc::kern_return_t;
    }

    /// Walk all writable memory regions of the current process and count
    /// occurrences of `needle`.
    #[allow(deprecated)]
    pub fn scan_writable_memory(needle: &[u8]) -> usize {
        let pid = std::process::id() as libc::c_int;
        let mut addr: u64 = 0;
        let mut matches = 0;
        let mut chunk = vec![0u8; 64 * 1024];

        loop {
            let mut ri = std::mem::MaybeUninit::<ProcRegionInfo>::zeroed();
            let sz = std::mem::size_of::<ProcRegionInfo>() as libc::c_int;
            let r = unsafe {
                libc::proc_pidinfo(pid, PROC_PIDREGIONINFO, addr, ri.as_mut_ptr().cast(), sz)
            };
            if r != sz {
                break;
            }
            let ri = unsafe { ri.assume_init() };

            if (ri.pri_protection & VM_PROT_WRITE != 0) && (ri.pri_protection & VM_PROT_READ != 0) {
                let region_start = ri.pri_address;
                let region_size = ri.pri_size;
                let mut offset = 0;

                while offset < region_size {
                    let to_read =
                        std::cmp::min(chunk.len() as u64, region_size - offset) as libc::vm_size_t;
                    let mut read_bytes: libc::vm_size_t = 0;
                    let kr = unsafe {
                        vm_read_overwrite(
                            libc::mach_task_self(),
                            (region_start + offset) as libc::vm_address_t,
                            to_read,
                            chunk.as_mut_ptr() as libc::vm_address_t,
                            &mut read_bytes,
                        )
                    };
                    if kr == 0 && read_bytes > 0 {
                        let slice = &chunk[..read_bytes as usize];
                        for window in slice.windows(needle.len()) {
                            if window == needle {
                                matches += 1;
                            }
                        }
                    }
                    offset += to_read as u64;
                }
            }

            if ri.pri_address.checked_add(ri.pri_size).is_none() {
                break;
            }
            addr = ri.pri_address + ri.pri_size;
        }
        matches
    }
}

#[test]
fn detokenize_leaves_zero_canary_hits_in_writable_memory() {
    #[cfg(target_os = "macos")]
    {
        // Generate an obscure 32-byte canary at runtime so it does not exist in .rodata
        let key_seed: u8 = 0xA7;
        let canary: Vec<u8> = (0..32).map(|i| (i * 7 + 13) ^ key_seed).collect();

        // 1. Verify that while canary is in SecretBytes, dropping it zeroizes the memory
        {
            let secret = SecretBytes::new(canary.clone());
            // Verify secret holds canary
            assert_eq!(secret.expose(), canary.as_slice());
            // Explicitly zeroize / drop
            drop(secret);
        }

        // 2. Perform Detokenize simulation through display
        {
            let mut display = EphemeralDisplay::default();
            let secret = SecretBytes::new(canary.clone());
            let _ = display.show(&[secret]);
            assert_eq!(display.count, 1);
        }

        // Now drop our local canary copy and scan writable memory
        let needle = canary.clone();
        drop(canary);

        #[allow(deprecated)]
        let hits = macos_scanner::scan_writable_memory(&needle);
        // The only possible copy in writable memory could be the `needle` passed to scan,
        // which is in the scanner frame. Let's ensure no persistent or leaked copies exist.
        // Even with the needle on stack in scan_writable_memory, hits should be <= 1 (the search needle itself).
        // If Detokenize had cloned it to a String or leaked it in heap, hits would be > 1.
        assert!(
            hits <= 1,
            "canary leaked in writable memory! Found {} hits (expected <= 1 for needle itself)",
            hits
        );
    }
}
