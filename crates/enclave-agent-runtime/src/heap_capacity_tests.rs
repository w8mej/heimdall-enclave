//! Synthetic owned allocations only. Observe initialized bytes while the real
//! refusal guard still owns them; never read freed memory or log payloads or
//! addresses. Spare capacity and physical erasure are not observed here.
use super::*;
use std::cell::RefCell;

#[derive(Clone, Debug, PartialEq, Eq)]
struct DroppedPayload { initialized: usize, allocation: usize, initialized_zero: bool }
thread_local! {
    static DROPS: RefCell<Option<Vec<DroppedPayload>>> = const { RefCell::new(None) };
}
pub(super) fn observe_pending_drop(secret: &SecretBytes) {
    let _ = DROPS.try_with(|slot| {
        if let Some(events) = slot.borrow_mut().as_mut() {
            events.push(DroppedPayload { initialized: secret.len(),
                allocation: secret.allocation_bytes(), initialized_zero: secret.is_wiped() });
        }
    });
}
struct DropCapture;
impl DropCapture {
    fn new() -> Self {
        DROPS.with(|slot| assert!(slot.replace(Some(Vec::new())).is_none())); Self
    }
    fn finish(self) -> Vec<DroppedPayload> {
        DROPS.with(|slot| slot.borrow_mut().take().expect("active payload observer"))
    }
}
impl Drop for DropCapture {
    fn drop(&mut self) { let _ = DROPS.try_with(|slot| slot.borrow_mut().take()); }
}
fn payload(capacity: usize, initialized: usize) -> Vec<u8> {
    assert!(initialized <= capacity);
    let mut bytes = Vec::with_capacity(capacity);
    bytes.resize(initialized, 0xa5); bytes
}
fn heap() -> CapabilityHeap {
    CapabilityHeap::new(enclave_core::seq::new_boot_epoch_id())
}
fn assert_dropped(events: &[DroppedPayload], initialized: usize, allocation: usize) {
    assert_eq!(events, &[DroppedPayload { initialized, allocation, initialized_zero: true }]);
}

#[test]
fn excess_capacity_refusal_scrubs_input_and_preserves_live_heap_and_exposure() {
    let mut h = heap();
    let keep = payload(64, 4); let keep_charge = keep.capacity();
    let stored = h.ingest_attachment(keep, "paste://keep").unwrap();
    let candidate = payload(256, 1); let charge = candidate.capacity();
    h.max_payload_bytes = keep_charge + charge - 1;
    let floor = h.literal_exposure();
    let observation = DropCapture::new();
    assert!(h.ingest_tool_output("t", &"aa".repeat(32), candidate, Conf::C4,
        &[], "synthetic://refused", VaultTier::A4).unwrap_err().is("CAPABILITY_HEAP_FULL"));
    assert_dropped(&observation.finish(), 1, charge);
    assert_eq!(h.resident, keep_charge); assert_eq!(h.len(), 1);
    assert_eq!(h.literal_exposure(), floor);
    assert_eq!(h.payload(&stored.handle).unwrap(), &[0xa5; 4]);
    h.verify_presented(&stored).unwrap();
}

#[test]
fn exact_capacity_boundary_release_and_reuse_preserve_original_allocation_and_other_values() {
    let mut h = heap();
    let keep = payload(32, 4); let keep_charge = keep.capacity();
    let parent = h.ingest_attachment(keep, "paste://parent").unwrap();
    let candidate = payload(128, 3); let charge = candidate.capacity(); let original = candidate.as_ptr();
    h.max_payload_bytes = keep_charge + charge;
    let observation = DropCapture::new();
    let derived = h.derive(&[parent.handle.clone()], Label::BOTTOM, candidate, "Bytes").unwrap();
    assert!(observation.finish().is_empty(), "successful transfer is not refusal cleanup");
    assert_eq!(h.resident, h.max_payload_bytes);
    let stored = h.get(&derived.handle).unwrap();
    assert!(std::ptr::eq(stored.payload.expose().as_ptr(), original));
    assert_eq!(stored.payload.allocation_bytes(), charge);
    assert_eq!(stored.payload.expose(), &[0xa5; 3]);
    assert_eq!(derived.label, parent.label); h.verify_presented(&derived).unwrap();
    assert!(h.release(&[derived.handle.clone(), "$v_unknown".into()]).is_err());
    assert_eq!(h.resident, h.max_payload_bytes);
    assert_eq!(h.release(&[derived.handle.clone(), derived.handle.clone()]).unwrap(), 1);
    assert_eq!(h.resident, keep_charge); assert_eq!(h.len(), 1);
    let replacement = payload(charge, 2); let replacement_charge = replacement.capacity();
    assert_eq!(replacement_charge, charge);
    let next = h.store_declassified(&parent.handle, replacement, parent.entity_keys.clone()).unwrap();
    assert_ne!(next.handle, derived.handle); assert_eq!(h.resident, keep_charge + replacement_charge);
    h.verify_presented(&next).unwrap();
    assert_eq!(h.release(&[next.handle]).unwrap(), 1); assert_eq!(h.resident, keep_charge);
    assert_eq!(h.payload(&parent.handle).unwrap(), &[0xa5; 4]);
    h.wipe(); assert_eq!(h.resident, 0); assert!(h.is_empty());
    assert!(h.verify_presented(&parent).is_err());
}

#[test]
fn empty_reserved_capacity_is_not_free_and_successful_release_restores_the_charge() {
    let mut h = heap(); h.max_payload_bytes = 0;
    let candidate = payload(128, 0); let charge = candidate.capacity();
    let observation = DropCapture::new();
    assert!(h.ingest_attachment(candidate, "paste://empty-refused").unwrap_err().is("CAPABILITY_HEAP_FULL"));
    assert_dropped(&observation.finish(), 0, charge);
    assert_eq!(h.resident, 0); assert!(h.is_empty());

    let candidate = payload(charge, 0); let charge = candidate.capacity(); let original = candidate.as_ptr();
    h.max_payload_bytes = charge;
    let observation = DropCapture::new();
    let stored = h.ingest_attachment(candidate, "paste://empty-admitted").unwrap();
    assert!(observation.finish().is_empty());
    let value = h.get(&stored.handle).unwrap();
    assert!(value.payload.is_empty()); assert_eq!(value.payload.allocation_bytes(), charge);
    assert!(std::ptr::eq(value.payload.expose().as_ptr(), original));
    assert_eq!(h.resident, charge);
    assert_eq!(h.release(&[stored.handle]).unwrap(), 1); assert_eq!(h.resident, 0);
    h.max_payload_bytes = 0;
    let no_allocation = h.ingest_attachment(Vec::new(), "paste://zero-capacity").unwrap();
    assert_eq!(h.resident, 0); assert_eq!(h.get(&no_allocation.handle).unwrap().payload.allocation_bytes(), 0);
    assert_eq!(h.release(&[no_allocation.handle]).unwrap(), 1);
}

fn ingress(kind: u8, h: &mut CapabilityHeap, parent: &IfcEnvelopeV1, bytes: Vec<u8>) -> EnclaveResult<IfcEnvelopeV1> {
    match kind {
        0 => h.ingest_tool_output("t", &"aa".repeat(32), bytes, Conf::C3, &[], "synthetic://tool", VaultTier::None),
        1 => h.ingest_derived_tool_output("t", &"aa".repeat(32), bytes, Conf::C3, &[], "synthetic://derived", VaultTier::None, &[parent.handle.clone()]),
        2 => h.ingest_attachment(bytes, "paste://candidate"),
        3 => h.derive(&[parent.handle.clone()], Label::BOTTOM, bytes, "Bytes"),
        4 => h.store_declassified(&parent.handle, bytes, parent.entity_keys.clone()),
        _ => unreachable!(),
    }
}

#[test]
fn every_actual_ingress_refuses_reserved_allocation_beyond_remaining_budget() {
    for kind in 0..5 {
        let mut h = heap();
        let parent_bytes = payload(32, 1); let parent_charge = parent_bytes.capacity();
        let parent = h.ingest_attachment(parent_bytes, "paste://parent").unwrap();
        let bytes = payload(128, 1); let charge = bytes.capacity();
        h.max_payload_bytes = parent_charge + charge - 1;
        let floor = h.literal_exposure();
        let observation = DropCapture::new();
        assert!(ingress(kind, &mut h, &parent, bytes).unwrap_err().is("CAPABILITY_HEAP_FULL"), "ingress {kind}");
        assert_dropped(&observation.finish(), 1, charge);
        assert_eq!(h.resident, parent_charge); assert_eq!(h.len(), 1);
        assert_eq!(h.literal_exposure(), floor); h.verify_presented(&parent).unwrap();
    }
}

#[test]
fn every_actual_ingress_transfers_same_allocation_at_exact_remaining_capacity() {
    for kind in 0..5 {
        let mut h = heap();
        let parent_bytes = payload(32, 1); let parent_charge = parent_bytes.capacity();
        let parent = h.ingest_attachment(parent_bytes, "paste://parent").unwrap();
        let bytes = payload(128, 1); let charge = bytes.capacity(); let original = bytes.as_ptr();
        h.max_payload_bytes = parent_charge + charge;
        let observation = DropCapture::new();
        let stored = ingress(kind, &mut h, &parent, bytes).unwrap();
        assert!(observation.finish().is_empty());
        assert_eq!(h.resident, h.max_payload_bytes); assert_eq!(h.len(), 2);
        let value = h.get(&stored.handle).unwrap();
        assert_eq!(value.payload.allocation_bytes(), charge);
        assert!(std::ptr::eq(value.payload.expose().as_ptr(), original));
        assert_eq!(value.payload.expose(), &[0xa5]); h.verify_presented(&stored).unwrap();
        assert_eq!(h.release(&[stored.handle]).unwrap(), 1); assert_eq!(h.resident, parent_charge);
        h.verify_presented(&parent).unwrap();
    }
}

#[test]
fn refusals_before_storage_retain_incoming_secret_cleanup_and_original_accounting() {
    for kind in 0..8 {
        let mut h = heap();
        let parent_bytes = payload(32, 1); let parent_charge = parent_bytes.capacity();
        let parent = h.ingest_attachment(parent_bytes, "paste://parent").unwrap();
        let bytes = payload(128, 5); let charge = bytes.capacity();
        let floor = h.literal_exposure(); let observation = DropCapture::new();
        let error = match kind {
            0 => h.derive(&["$v_unknown".into()], Label::BOTTOM, bytes, "Bytes").unwrap_err(),
            1 => h.ingest_derived_tool_output("t", &"aa".repeat(32), bytes, Conf::C3, &[], "synthetic://parent-refusal", VaultTier::None, &["$v_unknown".into()]).unwrap_err(),
            2 => h.ingest_tool_output("t", &"aa".repeat(32), bytes, Conf::C3,
                &vec!["entity".into(); MAX_ENTITY_FANIN + 1], "synthetic://fanin", VaultTier::None).unwrap_err(),
            3..=6 => { h.next = u64::MAX; ingress(kind - 2, &mut h, &parent, bytes).unwrap_err() }
            7 => h.ingest_tool_output("t", "invalid-digest", bytes, Conf::C3, &[], "synthetic://schema", VaultTier::None).unwrap_err(),
            _ => unreachable!(),
        };
        let expected = match kind { 0 | 1 => "HANDLE_FORGERY", 2 => "PROVENANCE_FANIN_EXCEEDED",
            3..=6 => "HANDLE_ID_EXHAUSTED", 7 => "BAD_TOOLS_LIST_DIGEST", _ => unreachable!() };
        assert!(error.is(expected), "refusal case {kind}: {error}");
        assert_dropped(&observation.finish(), 5, charge);
        assert_eq!(h.resident, parent_charge); assert_eq!(h.len(), 1);
        assert_eq!(h.literal_exposure(), floor); h.verify_presented(&parent).unwrap();
    }
}

#[test]
fn lowered_budget_refuses_even_zero_allocation_without_altering_existing_charge() {
    let mut h = heap(); let bytes = payload(32, 1); let charge = bytes.capacity();
    let stored = h.ingest_attachment(bytes, "paste://keep").unwrap();
    h.max_payload_bytes = charge - 1;
    let observation = DropCapture::new();
    assert!(h.ingest_attachment(Vec::new(), "paste://over-budget").unwrap_err().is("CAPABILITY_HEAP_FULL"));
    assert_dropped(&observation.finish(), 0, 0);
    assert_eq!(h.resident, charge); assert_eq!(h.len(), 1); h.verify_presented(&stored).unwrap();
    assert_eq!(h.release(&[stored.handle]).unwrap(), 1); assert_eq!(h.resident, 0);
}

#[test]
fn checked_capacity_overflow_refuses_before_accounting_or_exposure_changes() {
    let mut h = heap(); h.max_payload_bytes = usize::MAX;
    // Fault fixture: no allocation of this size occurs. Exercise the checked
    // arithmetic boundary rather than relying on allocator exhaustion.
    h.resident = usize::MAX;
    let bytes = payload(32, 1); let charge = bytes.capacity();
    let floor = h.literal_exposure(); let observation = DropCapture::new();
    assert!(h.ingest_attachment(bytes, "paste://overflow").unwrap_err().is("CAPABILITY_HEAP_FULL"));
    assert_dropped(&observation.finish(), 1, charge);
    assert_eq!(h.resident, usize::MAX); assert!(h.is_empty()); assert_eq!(h.literal_exposure(), floor);
}
