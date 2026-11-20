//! Registered ownership accounting for retained and cloned streamed witnesses.
//!
//! This is a capacity limit for the owners instrumented here. It is not a fixed
//! secure slab, allocator-overhead measurement, decode limit, or process RSS
//! limit. Caller-owned decoded ingress exists before registration. Other prover,
//! journal, frame and response copies require their own reservations.

use std::mem::{size_of, take};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use zeroize::Zeroize;

use crate::witness::WitnessFold;

/// Existing specification allowance, not an additional cache/trace allocation.
pub(crate) const WITNESS_CAPACITY_LIMIT: usize = 32 * 1024 * 1024;

#[derive(Debug)]
struct Budget {
    limit: usize,
    used: AtomicUsize,
}

impl Budget {
    fn reserve(self: &Arc<Self>, bytes: usize) -> EnclaveResult<WitnessLease> {
        let mut current = self.used.load(Ordering::Acquire);
        loop {
            let next = current
                .checked_add(bytes)
                .filter(|next| *next <= self.limit)
                .ok_or_else(|| err!(ENOMEM, "WITNESS_CAPACITY_FULL"))?;
            match self.used.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(WitnessLease { budget: self.clone(), bytes }),
                Err(observed) => current = observed,
            }
        }
    }
}

/// A capacity charge which remains live independently of a cache purge.
///
/// Keep this owner until all corresponding moved/cloned allocations are gone.
/// It does not scrub allocations separated from their sensitive-data owner.
#[derive(Debug)]
pub(crate) struct WitnessLease {
    budget: Arc<Budget>,
    bytes: usize,
}

impl WitnessLease {
    fn split(&mut self, bytes: usize) -> Self {
        assert!(bytes <= self.bytes, "witness lease ownership mismatch");
        self.bytes -= bytes;
        Self { budget: self.budget.clone(), bytes }
    }

    /// Join charges from the same resource domain without releasing either.
    pub(crate) fn merge(&mut self, mut other: Self) {
        assert!(Arc::ptr_eq(&self.budget, &other.budget), "different witness domains");
        self.bytes = self.bytes.checked_add(other.bytes).expect("bounded lease sum");
        other.bytes = 0;
    }

    /// Registered allocated capacity represented by this lease.
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }
}

impl Drop for WitnessLease {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

fn add(a: usize, b: usize) -> EnclaveResult<usize> {
    a.checked_add(b).ok_or_else(|| err!(ENOMEM, "WITNESS_CAPACITY_OVERFLOW"))
}

fn array_bytes<T>(capacity: usize) -> EnclaveResult<usize> {
    capacity
        .checked_mul(size_of::<T>())
        .ok_or_else(|| err!(ENOMEM, "WITNESS_CAPACITY_OVERFLOW"))
}

fn payload_capacity(fold: &WitnessFold) -> EnclaveResult<usize> {
    add(add(fold.scrubbed.capacity(), fold.c_raw.capacity())?, fold.h_ingress_mac.capacity())
}

fn payload_len(fold: &WitnessFold) -> EnclaveResult<usize> {
    add(add(fold.scrubbed.len(), fold.c_raw.len())?, fold.h_ingress_mac.len())
}

fn wipe_fold(fold: &mut WitnessFold) {
    fold.scrubbed.zeroize();
    fold.c_raw.zeroize();
    fold.h_ingress_mac.zeroize();
}

struct SensitiveFold(WitnessFold);

impl Drop for SensitiveFold {
    fn drop(&mut self) {
        wipe_fold(&mut self.0);
    }
}

#[derive(Default)]
struct SensitiveFolds(Vec<WitnessFold>);

impl SensitiveFolds {
    fn into_inner(mut self) -> Vec<WitnessFold> {
        take(&mut self.0)
    }
}

impl Drop for SensitiveFolds {
    fn drop(&mut self) {
        for fold in &mut self.0 {
            wipe_fold(fold);
        }
    }
}

// Field order releases the allocation before releasing its registered charge,
// including early returns and unwinding after successful registration.
struct RegisteredFolds {
    folds: SensitiveFolds,
    lease: WitnessLease,
}

struct Entry {
    // Canonical UUID text is fixed-sized inline metadata, counted in Entry.
    epoch: [u8; 36],
    fold: SensitiveFold,
    _payload: WitnessLease,
}

fn epoch_key(epoch: &str) -> EnclaveResult<[u8; 36]> {
    enclave_core::seq::validate_epoch_id(epoch)?;
    let mut key = [0; 36];
    key.copy_from_slice(epoch.as_bytes());
    Ok(key)
}

/// Snapshot counters for the precisely instrumented resource domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResourceUsage {
    /// Retained slots, excluding active snapshots.
    pub(crate) retained_entries: usize,
    /// Cached entry-vector allocation plus cached payload allocations.
    pub(crate) retained_capacity_bytes: usize,
    /// Cached, active-snapshot and explicitly reserved capacity in this domain.
    pub(crate) registered_capacity_bytes: usize,
    /// Shared registered-capacity ceiling.
    pub(crate) limit_bytes: usize,
}

/// Sensitive cloned witnesses and their independent capacity ownership.
pub(crate) struct WitnessSnapshot {
    folds: SensitiveFolds,
    lease: WitnessLease,
}

impl WitnessSnapshot {
    /// Transfer data and charge together to an operation owner.
    ///
    /// The caller must hold the lease until these allocations and any copies
    /// attributed to it are gone. New copies need additional capacity charges.
    pub(crate) fn into_parts(self) -> (Vec<WitnessFold>, WitnessLease) {
        (self.folds.into_inner(), self.lease)
    }
}

/// Transactional retained cache with shared active-snapshot accounting.
pub(crate) struct RetainedWitnessCache {
    entries: Vec<Entry>,
    metadata: WitnessLease,
    budget: Arc<Budget>,
}

impl RetainedWitnessCache {
    /// Create an empty registered-capacity domain.
    pub(crate) fn new(limit_bytes: usize) -> Self {
        let budget = Arc::new(Budget { limit: limit_bytes, used: AtomicUsize::new(0) });
        Self {
            entries: Vec::new(),
            metadata: WitnessLease { budget: budget.clone(), bytes: 0 },
            budget,
        }
    }

    /// Reserve additional explicitly instrumented owned capacity.
    pub(crate) fn reserve_owned_capacity(&self, bytes: usize) -> EnclaveResult<WitnessLease> {
        self.budget.reserve(bytes)
    }

    /// Atomically accept a complete batch, or preserve every existing entry.
    ///
    /// Duplicate IDs in one batch are rejected. This intentionally tightens the
    /// former last-in-batch-wins behavior; replacements across batches remain
    /// supported. Candidate and old owners overlap and both count until drop.
    pub(crate) fn ingest(
        &mut self,
        epoch: &str,
        folds: Vec<WitnessFold>,
        proven_floor: Option<u64>,
    ) -> EnclaveResult<()> {
        let mut incoming = SensitiveFolds(folds);
        let key = epoch_key(epoch)?;
        if incoming.0.is_empty() {
            return Ok(());
        }
        incoming.0.sort_unstable_by_key(|fold| fold.rpc_seq_u64);
        if incoming.0.windows(2).any(|pair| pair[0].rpc_seq_u64 == pair[1].rpc_seq_u64) {
            fail!(EINVAL, "WITNESS_DUPLICATE_SLOT");
        }
        if incoming.0.iter().any(|fold| proven_floor.is_some_and(|floor| fold.rpc_seq_u64 <= floor)) {
            fail!(EACCES, "WITNESS_ALREADY_PROVEN");
        }
        let mut candidate_bytes = array_bytes::<WitnessFold>(incoming.0.capacity())?;
        for fold in &incoming.0 {
            candidate_bytes = add(candidate_bytes, payload_capacity(fold)?)?;
        }
        let candidates = self.budget.reserve(candidate_bytes)?;
        let mut incoming = RegisteredFolds { folds: incoming, lease: candidates };
        let replaced = |entry: &Entry| {
            entry.epoch == key
                && incoming.folds.0.binary_search_by_key(&entry.fold.0.rpc_seq_u64, |fold| fold.rpc_seq_u64).is_ok()
        };
        let preserved = self.entries.iter().filter(|entry| !replaced(entry)).count();
        let final_len = add(preserved, incoming.folds.0.len())?;
        // This allocation is staging. It is measured and registered before any
        // cache mutation; allocation/decode transient peaks are not an RSS cap.
        let mut next = Vec::new();
        next.try_reserve_exact(final_len).map_err(|_| err!(ENOMEM, "WITNESS_ALLOCATION"))?;
        let next_metadata = self.budget.reserve(array_bytes::<Entry>(next.capacity())?)?;

        // No fallible operation or allocation remains after this point.
        let old = take(&mut self.entries);
        for entry in old {
            if !replaced(&entry) {
                next.push(entry);
            }
        }
        for fold in incoming.folds.0.drain(..) {
            let bytes = payload_capacity(&fold).expect("preflighted payload capacity");
            next.push(Entry {
                epoch: key,
                fold: SensitiveFold(fold),
                _payload: incoming.lease.split(bytes),
            });
        }
        self.entries = next;
        self.metadata = next_metadata;
        // incoming retains the now-empty inbound Vec's allocation charge
        // until both are dropped on return; it is never transferred to cache.
        Ok(())
    }

    /// Clone a selected range, retaining a charge after cache purge/retirement.
    pub(crate) fn snapshot_range(
        &self,
        epoch: &str,
        start: u64,
        end: u64,
    ) -> EnclaveResult<WitnessSnapshot> {
        let key = epoch_key(epoch)?;
        let selected = |entry: &&Entry| {
            entry.epoch == key && (start..=end).contains(&entry.fold.0.rpc_seq_u64)
        };
        let count = self.entries.iter().filter(selected).count();
        let mut minimum = array_bytes::<WitnessFold>(count)?;
        for entry in self.entries.iter().filter(selected) {
            minimum = add(minimum, payload_len(&entry.fold.0)?)?;
        }
        // Reserve requested clone sizes before allocating them. Any extra
        // allocator capacity is registered before the snapshot can escape.
        let mut lease = self.budget.reserve(minimum)?;
        let mut folds = SensitiveFolds::default();
        folds.0.try_reserve_exact(count).map_err(|_| err!(ENOMEM, "WITNESS_ALLOCATION"))?;
        let mut actual = array_bytes::<WitnessFold>(folds.0.capacity())?;
        for entry in self.entries.iter().filter(selected) {
            let source = &entry.fold.0;
            let mut clone = SensitiveFold(WitnessFold {
                rpc_seq_u64: source.rpc_seq_u64,
                scrubbed: Vec::new(),
                c_raw: String::new(),
                h_ingress_mac: String::new(),
            });
            clone.0.scrubbed.try_reserve_exact(source.scrubbed.len()).map_err(|_| err!(ENOMEM, "WITNESS_ALLOCATION"))?;
            clone.0.scrubbed.extend_from_slice(&source.scrubbed);
            clone.0.c_raw.try_reserve_exact(source.c_raw.len()).map_err(|_| err!(ENOMEM, "WITNESS_ALLOCATION"))?;
            clone.0.c_raw.push_str(&source.c_raw);
            clone.0.h_ingress_mac.try_reserve_exact(source.h_ingress_mac.len()).map_err(|_| err!(ENOMEM, "WITNESS_ALLOCATION"))?;
            clone.0.h_ingress_mac.push_str(&source.h_ingress_mac);
            actual = add(actual, payload_capacity(&clone.0)?)?;
            if actual > lease.bytes {
                lease.merge(self.budget.reserve(actual - lease.bytes)?);
            }
            folds.0.push(WitnessFold {
                rpc_seq_u64: clone.0.rpc_seq_u64,
                scrubbed: take(&mut clone.0.scrubbed),
                c_raw: take(&mut clone.0.c_raw),
                h_ingress_mac: take(&mut clone.0.h_ingress_mac),
            });
        }
        if actual > lease.bytes {
            lease.merge(self.budget.reserve(actual - lease.bytes)?);
        }
        Ok(WitnessSnapshot { folds, lease })
    }

    /// Retire only the acknowledged, committed range selected by the service.
    ///
    /// This method does not decide whether a proof/relay succeeded. It never
    /// clears authoritative proven floors or uncertain-delivery debt.
    pub(crate) fn retire_range(&mut self, epoch: &str, start: u64, end: u64) {
        self.entries.retain(|entry| {
            entry.epoch.as_slice() != epoch.as_bytes()
                || !(start..=end).contains(&entry.fold.0.rpc_seq_u64)
        });
    }

    /// Purge cache allocations; active snapshot/reservation leases stay charged.
    pub(crate) fn wipe(&mut self) {
        self.entries = Vec::new();
        self.metadata = WitnessLease { budget: self.budget.clone(), bytes: 0 };
    }

    /// Whether the retained cache has no slots (active owners may still exist).
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Current registered capacity, excluding allocator headers/fixed Arc state.
    pub(crate) fn usage(&self) -> ResourceUsage {
        let retained_capacity_bytes = self.entries.iter().fold(self.metadata.bytes, |sum, entry| {
            sum.checked_add(entry._payload.bytes).expect("bounded retained sum")
        });
        ResourceUsage {
            retained_entries: self.entries.len(),
            retained_capacity_bytes,
            registered_capacity_bytes: self.budget.used.load(Ordering::Acquire),
            limit_bytes: self.budget.limit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPOCH: &str = "12345678-1234-4234-8234-123456789abc";
    const OTHER: &str = "22345678-1234-4234-8234-123456789abc";

    fn fold(seq: u64, capacity: usize) -> WitnessFold {
        let mut scrubbed = Vec::with_capacity(capacity);
        scrubbed.extend_from_slice(b"x");
        WitnessFold {
            rpc_seq_u64: seq,
            scrubbed,
            c_raw: "c".repeat(64),
            h_ingress_mac: "a".repeat(64),
        }
    }

    #[test]
    fn capacity_not_length_is_registered_and_empty_epochs_keep_no_metadata() {
        let mut cache = RetainedWitnessCache::new(64 * 1024);
        cache.ingest(EPOCH, Vec::new(), None).unwrap();
        assert_eq!(cache.usage().registered_capacity_bytes, 0);
        let f = fold(1, 4096);
        let expected = payload_capacity(&f).unwrap();
        cache.ingest(EPOCH, vec![f], None).unwrap();
        let usage = cache.usage();
        assert_eq!(usage.retained_entries, 1);
        assert_eq!(usage.retained_capacity_bytes, cache.entries.capacity() * size_of::<Entry>() + expected);
        assert_eq!(usage.registered_capacity_bytes, usage.retained_capacity_bytes);
    }

    #[test]
    fn stale_duplicate_invalid_epoch_and_mixed_batches_are_transactional() {
        let mut cache = RetainedWitnessCache::new(64 * 1024);
        cache.ingest(EPOCH, vec![fold(5, 8)], None).unwrap();
        let before = cache.usage();
        assert!(cache.ingest(EPOCH, vec![fold(1, 8), fold(6, 8)], Some(1)).unwrap_err().is("WITNESS_ALREADY_PROVEN"));
        assert_eq!(cache.usage(), before);
        assert!(cache.ingest(EPOCH, vec![fold(6, 8), fold(6, 8)], None).unwrap_err().is("WITNESS_DUPLICATE_SLOT"));
        assert_eq!(cache.usage(), before);
        assert!(cache.ingest("bad", vec![fold(6, 8)], None).is_err());
        assert_eq!(cache.usage(), before);
    }

    #[test]
    fn aggregate_cross_epoch_and_replacement_overlap_refuse_without_mutation() {
        let mut cache = RetainedWitnessCache::new(64 * 1024);
        cache.ingest(EPOCH, vec![fold(1, 1024)], None).unwrap();
        let used = cache.usage().registered_capacity_bytes;
        // Occupy the remaining registered domain without touching cache.
        let held = cache.reserve_owned_capacity(cache.budget.limit - used).unwrap();
        let before = cache.usage();
        assert!(cache.ingest(OTHER, vec![fold(1, 8)], None).unwrap_err().is("WITNESS_CAPACITY_FULL"));
        assert_eq!(cache.usage(), before);
        assert!(cache.ingest(EPOCH, vec![fold(1, 8)], None).unwrap_err().is("WITNESS_CAPACITY_FULL"));
        assert_eq!(cache.usage(), before);
        drop(held);
        cache.ingest(EPOCH, vec![fold(1, 8)], None).unwrap();
        assert_eq!(cache.usage().retained_entries, 1);
        assert!(cache.usage().registered_capacity_bytes < used);
    }

    #[test]
    fn snapshot_charge_survives_wipe_until_the_active_owner_drops() {
        let mut cache = RetainedWitnessCache::new(64 * 1024);
        cache.ingest(EPOCH, vec![fold(1, 1024)], None).unwrap();
        let snapshot = cache.snapshot_range(EPOCH, 1, 1).unwrap();
        let (mut folds, lease) = snapshot.into_parts();
        let active = lease.bytes();
        assert!(active > 0);
        cache.wipe();
        assert!(cache.is_empty());
        assert_eq!(cache.usage().retained_capacity_bytes, 0);
        assert_eq!(cache.usage().registered_capacity_bytes, active);
        for fold in &mut folds { wipe_fold(fold); }
        drop(folds);
        drop(lease);
        assert_eq!(cache.usage().registered_capacity_bytes, 0);
    }

    #[test]
    fn snapshot_refusal_preserves_cache_and_releases_partial_reservations() {
        let mut cache = RetainedWitnessCache::new(64 * 1024);
        cache.ingest(EPOCH, vec![fold(1, 1024)], None).unwrap();
        let before = cache.usage();
        let held = cache.reserve_owned_capacity(before.limit_bytes - before.registered_capacity_bytes).unwrap();
        let full = cache.usage();
        let result = cache.snapshot_range(EPOCH, 1, 1);
        assert!(matches!(result, Err(error) if error.is("WITNESS_CAPACITY_FULL")));
        assert_eq!(cache.usage(), full);
        drop(held);
        assert_eq!(cache.usage(), before);
        let snapshot = cache.snapshot_range(EPOCH, 1, 1).unwrap();
        let active = snapshot.lease.bytes();
        let domain = cache.budget.clone();
        drop(cache);
        assert_eq!(domain.used.load(Ordering::Acquire), active);
        drop(snapshot);
        assert_eq!(domain.used.load(Ordering::Acquire), 0);
    }

    #[test]
    fn retirement_preserves_other_epochs_and_uncovered_slots_and_metadata_charge() {
        let mut cache = RetainedWitnessCache::new(64 * 1024);
        cache.ingest(EPOCH, vec![fold(1, 8), fold(2, 8), fold(3, 8)], None).unwrap();
        cache.ingest(OTHER, vec![fold(2, 8)], None).unwrap();
        cache.retire_range(EPOCH, 1, 2);
        assert_eq!(cache.usage().retained_entries, 2);
        assert!(cache.entries.iter().any(|entry| entry.epoch.as_slice() == OTHER.as_bytes()));
        assert!(cache.entries.iter().any(|entry| entry.fold.0.rpc_seq_u64 == 3));
        cache.retire_range(EPOCH, 3, 3);
        cache.retire_range(OTHER, 2, 2);
        assert!(cache.is_empty());
        assert!(cache.usage().registered_capacity_bytes > 0);
        cache.wipe();
        assert_eq!(cache.usage().registered_capacity_bytes, 0);
    }

    #[test]
    fn overflow_and_overbudget_reservations_do_not_change_the_domain() {
        let cache = RetainedWitnessCache::new(16);
        let held = cache.reserve_owned_capacity(8).unwrap();
        assert!(cache.reserve_owned_capacity(usize::MAX).unwrap_err().is("WITNESS_CAPACITY_FULL"));
        assert!(array_bytes::<WitnessFold>(usize::MAX).unwrap_err().is("WITNESS_CAPACITY_OVERFLOW"));
        assert_eq!(cache.usage().registered_capacity_bytes, 8);
        drop(held);
        assert_eq!(cache.usage().registered_capacity_bytes, 0);
    }
}
