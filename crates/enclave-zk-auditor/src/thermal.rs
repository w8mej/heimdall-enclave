//! Registered ownership for the `.serious` thermal RAM queue.
//!
//! The existing 12 MiB allowance covers conservative incoming payload capacity
//! plus actual queue-entry allocation, including old/new metadata overlap while
//! growing. This is not an allocator/RSS peak bound, encrypted queue, locked
//! arena, scheduler or producer backpressure protocol. Decoded input already
//! exists before admission, and a staged allocation is measured after creation.
//! SecretBytes retains the incoming allocation and existing best-effort mlock; no
//! historical allocator-copy or physical-erasure guarantee is added here.

use std::collections::VecDeque;
use std::mem::{size_of, take};

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use enclave_core::secret::SecretBytes;
use zeroize::Zeroizing;

/// Existing queue allowance; metadata is included, not an additional arena.
pub const SERIOUS_QUEUE_CAP: usize = 12 * 1024 * 1024;
const INITIAL_METADATA_ENTRIES: usize = 4;

#[derive(Debug)]
struct Entry {
    secret: SecretBytes,
    // SecretBytes::new retains its allocation. The original incoming Vec
    // capacity remains charged until this queue entry leaves.
    input_capacity: usize,
}

/// Precisely defined queue ownership gauges, separate from process memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceUsage {
    /// Number of queued entries, including empty payloads.
    pub entries: usize,
    /// Sum of initialized queued payload lengths; informational, not recharged.
    pub payload_bytes: usize,
    /// Sum of original incoming Vec capacities for the queued payloads.
    pub payload_registered_capacity_bytes: usize,
    /// Actual VecDeque entry capacity times size_of::<Entry>().
    pub metadata_capacity_bytes: usize,
    /// Registered payload capacity plus metadata capacity.
    pub registered_capacity_bytes: usize,
    /// Fixed production allowance, or an explicit private test allowance.
    pub limit_bytes: usize,
}

/// FIFO owners with transactional, capacity-based admission.
#[derive(Debug)]
pub struct ThermalQueue {
    items: VecDeque<Entry>,
    bytes: usize,
    payload_capacity: usize,
    metadata_capacity: usize,
    limit: usize,
}

fn add(a: usize, b: usize) -> EnclaveResult<usize> {
    a.checked_add(b).ok_or_else(|| err!(ENOMEM, "THERMAL_QUEUE_CAPACITY_OVERFLOW"))
}

fn metadata_bytes(capacity: usize) -> EnclaveResult<usize> {
    capacity.checked_mul(size_of::<Entry>())
        .ok_or_else(|| err!(ENOMEM, "THERMAL_QUEUE_CAPACITY_OVERFLOW"))
}

fn growth_target(current: usize, needed: usize) -> EnclaveResult<usize> {
    let doubled = current.checked_mul(2)
        .ok_or_else(|| err!(ENOMEM, "THERMAL_QUEUE_CAPACITY_OVERFLOW"))?;
    Ok(doubled.max(INITIAL_METADATA_ENTRIES).max(needed))
}

fn ensure_fits(charge: usize, limit: usize) -> EnclaveResult<()> {
    if charge > limit {
        fail!(ENOMEM, "THERMAL_QUEUE_FULL", "registered capacity {charge} > {limit}");
    }
    Ok(())
}

impl Default for ThermalQueue {
    fn default() -> Self { Self::empty(SERIOUS_QUEUE_CAP) }
}

impl ThermalQueue {
    fn empty(limit: usize) -> Self {
        Self { items: VecDeque::new(), bytes: 0, payload_capacity: 0,
            metadata_capacity: 0, limit }
    }

    /// Smaller deterministic domains for service/unit fixtures only.
    #[cfg(test)]
    pub(crate) fn with_limit(limit: usize) -> Self { Self::empty(limit) }

    /// Enqueue a deferred witness/frame. The incoming owner is zeroizing before
    /// any ordinary refusal; successful registration charges its original cap.
    pub fn push(&mut self, bytes: Vec<u8>) -> EnclaveResult<()> {
        self.push_guarded(Zeroizing::new(bytes))
    }

    /// Transfer a candidate guarded before dispatcher State/sequence/policy
    /// failures. This never clones or unwraps the candidate before admission.
    pub(crate) fn push_guarded(&mut self, mut candidate: Zeroizing<Vec<u8>>) -> EnclaveResult<()> {
        let input_capacity = candidate.capacity();
        let payload_capacity = add(self.payload_capacity, input_capacity)?;
        let payload_bytes = add(self.bytes, candidate.len())?;
        let needed = add(self.items.len(), 1)?;
        ensure_fits(add(payload_capacity, self.metadata_capacity)?, self.limit)?;

        // Reserve a separate geometric metadata owner only when the live deque
        // is full. No fallible reserve or later cap check mutates the live FIFO.
        let replacement = if needed > self.items.capacity() {
            let target = growth_target(self.items.capacity(), needed)?;
            let proposed_metadata = metadata_bytes(target)?;
            ensure_fits(add(add(payload_capacity, self.metadata_capacity)?, proposed_metadata)?, self.limit)?;
            let mut staged = VecDeque::new();
            staged.try_reserve_exact(target)
                .map_err(|_| err!(ENOMEM, "THERMAL_QUEUE_ALLOCATION"))?;
            let actual_metadata = metadata_bytes(staged.capacity())?;
            // Count actual old + new allocation overlap before moving anything.
            // Actual allocation is measured after creation: transient allocator
            // overshoot and allocator headers are not a physical-peak claim.
            ensure_fits(add(add(payload_capacity, self.metadata_capacity)?, actual_metadata)?, self.limit)?;
            Some((staged, actual_metadata))
        } else { None };

        // All ordinary fallible work precedes mutation. The existing constructor
        // retains the incoming allocation and performs best-effort mlock.
        let entry = Entry { secret: SecretBytes::new(take(&mut *candidate)), input_capacity };
        if let Some((mut staged, actual_metadata)) = replacement {
            while let Some(previous) = self.items.pop_front() { staged.push_back(previous); }
            staged.push_back(entry); // Reserved space includes this entry.
            let old_metadata = std::mem::replace(&mut self.items, staged);
            drop(old_metadata); // Free old metadata before dropping its charge.
            self.metadata_capacity = actual_metadata;
        } else {
            self.items.push_back(entry); // Existing spare metadata; no growth.
        }
        self.bytes = payload_bytes;
        self.payload_capacity = payload_capacity;
        Ok(())
    }

    /// Transfer the oldest secret unchanged to the caller. Its returned owner
    /// leaves this queue's capacity domain; the caller must account its lifetime.
    pub fn pop(&mut self) -> Option<SecretBytes> {
        let front = self.items.front()?;
        // Check both releases before mutation. An impossible internal accounting
        // violation fails closed rather than wrapping or hiding retained data.
        let bytes = self.bytes.checked_sub(front.secret.len())
            .expect("thermal queue payload length invariant");
        let payload_capacity = self.payload_capacity.checked_sub(front.input_capacity)
            .expect("thermal queue payload capacity invariant");
        let entry = self.items.pop_front().expect("front was present");
        self.bytes = bytes;
        self.payload_capacity = payload_capacity;
        Some(entry.secret)
    }

    /// Queued initialized payload bytes; preserves the existing API definition.
    pub fn bytes(&self) -> usize { self.bytes }

    /// Queue-owned registered capacity, not actual SecretBytes capacity or RSS.
    pub fn resource_usage(&self) -> ResourceUsage {
        ResourceUsage { entries: self.items.len(), payload_bytes: self.bytes,
            payload_registered_capacity_bytes: self.payload_capacity,
            metadata_capacity_bytes: self.metadata_capacity,
            registered_capacity_bytes: self.payload_capacity.checked_add(self.metadata_capacity)
                .expect("thermal queue registered capacity invariant"),
            limit_bytes: self.limit }
    }

    /// Wipe owned payloads and actually free queue metadata (yank/lid-close).
    pub fn wipe(&mut self) {
        let old = take(&mut self.items);
        drop(old); // SecretBytes normal drop scrubs before ownership is released.
        self.bytes = 0;
        self.payload_capacity = 0;
        self.metadata_capacity = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_enforced() {
        let mut queue = ThermalQueue::default();
        queue.push(vec![0u8; 8 * 1024 * 1024]).unwrap();
        let before = queue.resource_usage();
        // Four MiB more cannot fit: payloads and metadata share the allowance.
        assert!(queue.push(vec![0u8; 4 * 1024 * 1024]).unwrap_err().is("THERMAL_QUEUE_FULL"));
        assert_eq!(queue.resource_usage(), before);
        queue.pop().unwrap();
        queue.push(vec![0u8; 1]).unwrap();
        queue.wipe();
        assert_eq!(queue.bytes(), 0);
        assert_eq!(queue.resource_usage().registered_capacity_bytes, 0);
    }

    #[test]
    fn spare_capacity_is_conservatively_registered_and_refusal_preserves_fifo() {
        let mut queue = ThermalQueue::with_limit(64 * 1024);
        let mut input = Vec::with_capacity(4096);
        input.extend_from_slice(b"a");
        let original_capacity = input.capacity();
        queue.push(input).unwrap();
        let before = queue.resource_usage();
        assert_eq!(before.payload_bytes, 1);
        assert_eq!(before.payload_registered_capacity_bytes, original_capacity);
        assert_eq!(before.registered_capacity_bytes,
            original_capacity + before.metadata_capacity_bytes);
        let mut rejected = Vec::with_capacity(before.limit_bytes);
        rejected.extend_from_slice(b"refused");
        assert!(queue.push(rejected).unwrap_err().is("THERMAL_QUEUE_FULL"));
        assert_eq!(queue.resource_usage(), before);
        assert_eq!(queue.pop().unwrap().expose(), b"a");
    }

    #[test]
    fn empty_entries_are_admitted_but_metadata_growth_is_geometric_and_bounded() {
        let mut queue = ThermalQueue::with_limit(4096);
        let bound = 4096 / size_of::<Entry>() + 1;
        let mut growths = 0;
        let mut refused = false;
        for _ in 0..bound {
            let before = queue.resource_usage();
            match queue.push(Vec::new()) {
                Ok(()) => {
                    let after = queue.resource_usage();
                    assert_eq!(after.entries, before.entries + 1);
                    assert_eq!(after.payload_bytes, 0);
                    assert_eq!(after.payload_registered_capacity_bytes, 0);
                    assert!(after.metadata_capacity_bytes > 0);
                    assert!(after.registered_capacity_bytes <= after.limit_bytes);
                    if after.metadata_capacity_bytes != before.metadata_capacity_bytes {
                        assert!(before.metadata_capacity_bytes == 0
                            || after.metadata_capacity_bytes >= before.metadata_capacity_bytes * 2);
                        growths += 1;
                    }
                }
                Err(error) => {
                    assert!(error.is("THERMAL_QUEUE_FULL"), "{error}");
                    assert_eq!(queue.resource_usage(), before);
                    refused = true;
                    break;
                }
            }
        }
        assert!(queue.resource_usage().entries > 0, "empty input is valid");
        assert!(refused, "metadata-only ingress must eventually refuse");
        assert!(growths <= (usize::BITS - bound.leading_zeros()) as usize + 1,
            "metadata growth must not copy the whole queue for every entry");
    }

    #[test]
    fn metadata_overlap_refusal_is_transactional_and_pop_keeps_metadata_charged() {
        // Learn the actual first allocation instead of assuming allocator size.
        let mut probe = ThermalQueue::with_limit(4096);
        probe.push(Vec::new()).unwrap();
        let metadata = probe.resource_usage().metadata_capacity_bytes;
        let entries = probe.items.capacity();
        probe.wipe();
        let mut queue = ThermalQueue::with_limit(metadata * 2);
        for _ in 0..entries { queue.push(Vec::new()).unwrap(); }
        let before = queue.resource_usage();
        assert!(queue.push(Vec::new()).unwrap_err().is("THERMAL_QUEUE_FULL"));
        assert_eq!(queue.resource_usage(), before,
            "old + new metadata overlap cannot mutate a refused queue");
        let transferred = queue.pop().unwrap();
        assert!(transferred.is_empty());
        assert_eq!(queue.resource_usage().metadata_capacity_bytes, metadata);
        assert_eq!(queue.resource_usage().registered_capacity_bytes, metadata);
        queue.push(Vec::new()).unwrap(); // Reuse the existing spare entry.
        assert_eq!(queue.resource_usage(), before);
    }

    #[test]
    fn fifo_pop_transfers_the_existing_owner_and_releases_only_payload_charge() {
        let mut queue = ThermalQueue::with_limit(4096);
        for bytes in [b"a".as_slice(), b"bc".as_slice(), b"def".as_slice()] {
            queue.push(bytes.to_vec()).unwrap();
        }
        let metadata = queue.resource_usage().metadata_capacity_bytes;
        let mut transferred = Vec::new();
        for expected in [b"a".as_slice(), b"bc".as_slice(), b"def".as_slice()] {
            let before = queue.resource_usage();
            let old_pointer = queue.items.front().unwrap().secret.expose().as_ptr();
            let old_charge = queue.items.front().unwrap().input_capacity;
            let secret = queue.pop().unwrap();
            assert_eq!(secret.expose(), expected);
            assert_eq!(secret.expose().as_ptr(), old_pointer, "pop must move, not clone");
            let after = queue.resource_usage();
            assert_eq!(after.payload_bytes, before.payload_bytes - expected.len());
            assert_eq!(after.payload_registered_capacity_bytes,
                before.payload_registered_capacity_bytes - old_charge);
            assert_eq!(after.metadata_capacity_bytes, metadata);
            transferred.push(secret); // Caller-owned bytes are outside the queue.
        }
        assert!(queue.pop().is_none());
        assert_eq!(queue.resource_usage().registered_capacity_bytes, metadata);
        assert_eq!(transferred.len(), 3);
    }

    #[test]
    fn checked_capacity_arithmetic_and_zero_limit_refuse_without_wraparound() {
        for error in [add(usize::MAX, 1).unwrap_err(),
            metadata_bytes(usize::MAX).unwrap_err(),
            growth_target(usize::MAX, usize::MAX).unwrap_err()] {
            assert!(error.is("THERMAL_QUEUE_CAPACITY_OVERFLOW"));
        }
        let mut queue = ThermalQueue::with_limit(0);
        let before = queue.resource_usage();
        assert!(queue.push_guarded(Zeroizing::new(vec![7; 16])).unwrap_err().is("THERMAL_QUEUE_FULL"));
        assert_eq!(queue.resource_usage(), before);
        assert!(queue.push(Vec::new()).unwrap_err().is("THERMAL_QUEUE_FULL"));
        assert_eq!(queue.resource_usage(), before);
    }

    #[test]
    fn wipe_frees_entry_allocation_and_allows_fresh_admission() {
        let mut queue = ThermalQueue::with_limit(4096);
        queue.push(b"retained-sensitive-owner".to_vec()).unwrap();
        queue.push(Vec::new()).unwrap();
        assert!(queue.resource_usage().metadata_capacity_bytes > 0);
        assert!(queue.bytes() > 0);
        queue.wipe();
        assert_eq!(queue.items.capacity(), 0, "wipe must free deque metadata");
        assert_eq!(queue.resource_usage(), ResourceUsage {
            entries: 0, payload_bytes: 0, payload_registered_capacity_bytes: 0,
            metadata_capacity_bytes: 0, registered_capacity_bytes: 0, limit_bytes: 4096,
        });
        queue.wipe();
        queue.push(b"fresh".to_vec()).unwrap();
        assert_eq!(queue.pop().unwrap().expose(), b"fresh");
    }

    #[test]
    fn zero_length_flood_is_refused_by_registered_metadata_bound() {
        let mut queue = ThermalQueue::default();
        // Existing API only: even empty entries own VecDeque metadata. The old
        // SecretBytes-only metadata lower bound needs at most about 16 MiB of
        // actual deque allocation before demonstrating the unbounded admission.
        let attempts = SERIOUS_QUEUE_CAP / std::mem::size_of::<SecretBytes>() + 1;
        let mut refused = false;
        for _ in 0..attempts {
            match queue.push(Vec::new()) {
                Ok(()) => (),
                Err(error) => {
                    assert!(error.is("THERMAL_QUEUE_FULL"), "{error}");
                    refused = true;
                    break;
                }
            }
        }
        assert!(refused, "empty queue entries must consume the finite metadata allowance");
    }

}
