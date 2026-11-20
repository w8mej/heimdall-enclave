//! Multi-tenant PagedAttention KV-cache memory manager (FS-701 §4.1, GAP-58).
//!
//! Guarantees strict physical memory isolation across concurrent model tenants,
//! ensuring disjoint block table allocation and verified zeroization of recycled
//! memory blocks before reallocation.

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use std::collections::{HashMap, HashSet};

/// Default block size in 16-bit float elements (e.g. 16 tokens × 128 head dim).
pub const DEFAULT_BLOCK_TOKENS: usize = 16;

/// A physical memory block allocated from unified memory for KV-cache tensors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalBlock {
    /// Global block identifier.
    pub block_id: u32,
    /// Physical byte capacity.
    pub byte_size: usize,
    /// In-memory buffer storing the zeroized or active KV tensor state.
    pub data: Vec<u8>,
}

impl PhysicalBlock {
    /// Create a new zeroized physical block.
    pub fn new(block_id: u32, byte_size: usize) -> Self {
        Self {
            block_id,
            byte_size,
            data: vec![0u8; byte_size],
        }
    }

    /// Verify whether the physical block is completely zeroized.
    pub fn is_zeroed(&self) -> bool {
        self.data.iter().all(|&b| b == 0)
    }

    /// Zeroize the physical block memory.
    pub fn zeroize(&mut self) {
        for b in &mut self.data {
            unsafe { std::ptr::write_volatile(b, 0) };
        }
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Multi-tenant PagedAttention memory manager.
#[derive(Debug)]
pub struct PagedAttentionBlockManager {
    /// Block byte size (e.g. 4096 bytes).
    block_byte_size: usize,
    /// Pool of all physical blocks.
    blocks: Vec<PhysicalBlock>,
    /// Set of free block IDs available for allocation.
    free_blocks: Vec<u32>,
    /// Per-tenant block tables mapping logical block indices to physical block IDs.
    tenant_block_tables: HashMap<u64, Vec<u32>>,
}

impl PagedAttentionBlockManager {
    /// Initialize manager with `total_blocks` of `block_byte_size` bytes each.
    pub fn new(total_blocks: u32, block_byte_size: usize) -> Self {
        let mut blocks = Vec::with_capacity(total_blocks as usize);
        let mut free_blocks = Vec::with_capacity(total_blocks as usize);
        for id in 0..total_blocks {
            blocks.push(PhysicalBlock::new(id, block_byte_size));
            free_blocks.push(id);
        }
        Self {
            block_byte_size,
            blocks,
            free_blocks,
            tenant_block_tables: HashMap::new(),
        }
    }

    /// Return the block byte size.
    pub fn block_byte_size(&self) -> usize {
        self.block_byte_size
    }

    /// Allocate `num_blocks` for `tenant_id`.
    /// Blocks are guaranteed to be zeroized before assignment.
    pub fn allocate_blocks(
        &mut self,
        tenant_id: u64,
        num_blocks: usize,
    ) -> EnclaveResult<Vec<u32>> {
        if self.free_blocks.len() < num_blocks {
            fail!(
                ENOMEM,
                "PAGED_ATTENTION_OOM",
                "insufficient free physical blocks"
            );
        }
        let mut assigned = Vec::with_capacity(num_blocks);
        for _ in 0..num_blocks {
            let block_id = self
                .free_blocks
                .pop()
                .ok_or_else(|| err!(ENOMEM, "PAGED_ATTENTION_OOM", "pool empty"))?;
            let block = &mut self.blocks[block_id as usize];
            if !block.is_zeroed() {
                block.zeroize();
            }
            assigned.push(block_id);
        }
        self.tenant_block_tables
            .entry(tenant_id)
            .or_default()
            .extend(assigned.iter().copied());
        Ok(assigned)
    }

    /// Free all physical blocks allocated to `tenant_id`, zeroizing every block.
    pub fn free_tenant_blocks(&mut self, tenant_id: u64) -> EnclaveResult<usize> {
        let block_ids = match self.tenant_block_tables.remove(&tenant_id) {
            Some(b) => b,
            None => return Ok(0),
        };
        let count = block_ids.len();
        for id in block_ids {
            let block = &mut self.blocks[id as usize];
            block.zeroize();
            self.free_blocks.push(id);
        }
        Ok(count)
    }

    /// Return all physical block IDs assigned to `tenant_id`.
    pub fn tenant_blocks(&self, tenant_id: u64) -> &[u32] {
        self.tenant_block_tables
            .get(&tenant_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Verify physical memory disjointness across two tenant IDs.
    pub fn are_tenants_disjoint(&self, tenant_a: u64, tenant_b: u64) -> bool {
        if tenant_a == tenant_b {
            return false;
        }
        let set_a: HashSet<u32> = self.tenant_blocks(tenant_a).iter().copied().collect();
        let set_b: HashSet<u32> = self.tenant_blocks(tenant_b).iter().copied().collect();
        set_a.is_disjoint(&set_b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cross_tenant_isolation_disjointness() {
        let mut mgr = PagedAttentionBlockManager::new(64, 4096);
        let blocks_t1 = mgr.allocate_blocks(1, 4).unwrap();
        let blocks_t2 = mgr.allocate_blocks(2, 4).unwrap();

        assert_eq!(blocks_t1.len(), 4);
        assert_eq!(blocks_t2.len(), 4);
        assert!(mgr.are_tenants_disjoint(1, 2));

        // T1 blocks have no intersection with T2
        for b in &blocks_t1 {
            assert!(!blocks_t2.contains(b));
        }

        // Free T1 blocks and reallocate to T3
        mgr.free_tenant_blocks(1).unwrap();
        let blocks_t3 = mgr.allocate_blocks(3, 4).unwrap();
        assert!(mgr.are_tenants_disjoint(2, 3));
        for b in &blocks_t3 {
            assert!(mgr.blocks[*b as usize].is_zeroed());
        }
    }
}
