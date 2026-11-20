//! Private software fixtures exercise the production walker/owner and real
//! UsbSelection transitions. They do not construct native-monitor success.
use super::*;
use std::{cell::{Cell, RefCell}, collections::BTreeMap, rc::Rc, time::Duration};

fn end() -> Instant { Instant::now() + Duration::from_secs(5) }
fn hint() -> AttachmentHint { AttachmentHint { version: 1, service_registry_id: 10 } }

#[derive(Clone)]
struct Store { state: Rc<RefCell<UsbSelection>>, wipes: Rc<Cell<usize>> }
impl Store {
    fn new() -> Self {
        let mut state = UsbSelection::default();
        state.monitor_started().unwrap();
        Self { state: Rc::new(RefCell::new(state)), wipes: Rc::new(Cell::new(0)) }
    }
    fn instance(&self, id: u64) -> SelectedUsbInstance {
        SelectedUsbInstance::new_observed(id, vec![20, 1], UsbObservationEpoch(self.state.borrow().event_epoch)).unwrap()
    }
}
struct Guard { store: Store, generation: u64 }
impl Drop for Guard {
    fn drop(&mut self) {
        let invalidate = self.store.state.borrow_mut().release(self.generation);
        if invalidate {
            // A real callback may inspect topology. This borrow must succeed:
            // production guard invalidation likewise runs outside its mutex.
            assert!(self.store.state.try_borrow_mut().is_ok());
            self.store.wipes.set(self.store.wipes.get() + 1);
        }
    }
}
impl SelectionStore for Store {
    type Guard = Guard;
    fn observation(&self) -> EnclaveResult<(u64, UsbObservationEpoch)> {
        let state = self.state.borrow();
        monitor_current(&state, state.monitor_generation)?;
        Ok((state.monitor_generation, UsbObservationEpoch(state.event_epoch)))
    }
    fn bind_generation(&self, monitor: u64, instance: SelectedUsbInstance) -> EnclaveResult<u64> {
        let mut state = self.state.borrow_mut();
        monitor_current(&state, monitor)?;
        state.bind(instance)
    }
    fn own_generation(&self, generation: u64) -> Guard { Guard { store: self.clone(), generation } }
    fn generation(&self, guard: &Guard) -> u64 { guard.generation }
    fn revoke(&self, generation: u64) { drop(self.own_generation(generation)); }
    fn require(&self, monitor: u64, guard: &Guard) -> EnclaveResult<()> {
        let state = self.state.borrow();
        monitor_current(&state, monitor)?;
        state.require(Some(guard.generation), 1)
    }
}
#[derive(Default)]
struct HealthFixture { calls: Cell<usize>, fail_at: Cell<usize> }
impl Health for HealthFixture {
    fn observe(&self, until: Instant) -> EnclaveResult<()> {
        within(until)?;
        let next = self.calls.get() + 1;
        self.calls.set(next);
        if self.fail_at.get() == next { fail!(EIO, "FIXTURE_MONITOR_UNAVAILABLE"); }
        Ok(())
    }
}
struct Object { id: u64, token: u64, live: Rc<Cell<usize>> }
impl Drop for Object { fn drop(&mut self) { self.live.set(self.live.get() - 1); } }
struct RegistryData {
    parents: BTreeMap<u64, u64>, live: Rc<Cell<usize>>, lookups: usize,
    usb: bool, lookup_id: u64, incarnation: u64,
    parent_error: Option<u64>, identity_error: Option<u64>, root_id: u64,
    terminate_at: Option<(usize, Vec<Option<u64>>)>,
}
#[derive(Clone)]
struct FixtureRegistry { data: Rc<RefCell<RegistryData>>, store: Store }
impl FixtureRegistry {
    fn new(store: Store) -> Self {
        Self { store, data: Rc::new(RefCell::new(RegistryData {
            parents: [(10, 20), (20, 1)].into_iter().collect(), live: Rc::new(Cell::new(0)),
            lookups: 0, usb: true, lookup_id: 10, incarnation: 1,
            parent_error: None, identity_error: None, root_id: 1, terminate_at: None,
        })) }
    }
    fn object(&self, id: u64) -> Object {
        let data = self.data.borrow();
        data.live.set(data.live.get() + 1);
        Object { id, token: if id == 10 { data.incarnation } else { 1 }, live: data.live.clone() }
    }
}
impl Registry for FixtureRegistry {
    type Object = Object;
    fn root(&mut self) -> EnclaveResult<Object> {
        let id = self.data.borrow().root_id;
        Ok(self.object(id))
    }
    fn lookup(&mut self, _: u64) -> EnclaveResult<Object> {
        let (id, terminate) = {
            let mut data = self.data.borrow_mut();
            data.lookups += 1;
            (data.lookup_id, data.terminate_at.as_ref().filter(|(at, _)| *at == data.lookups).map(|(_, ids)| ids.clone()))
        };
        if let Some(ids) = terminate { self.store.state.borrow_mut().terminate(&ids); }
        Ok(self.object(id))
    }
    fn identity(&mut self, object: &Object) -> EnclaveResult<u64> {
        if self.data.borrow().identity_error == Some(object.id) { fail!(EIO, "FIXTURE_IDENTITY_ERROR"); }
        Ok(object.id)
    }
    fn is_usb(&mut self, _: &Object) -> bool { self.data.borrow().usb }
    fn equal(&mut self, left: &Object, right: &Object) -> bool { (left.id, left.token) == (right.id, right.token) }
    fn parent(&mut self, object: &Object) -> EnclaveResult<Object> {
        let id = {
            let data = self.data.borrow();
            if data.parent_error == Some(object.id) { fail!(EIO, "FIXTURE_PARENT_ERROR"); }
            *data.parents.get(&object.id).ok_or_else(|| err!(EIO, "FIXTURE_NO_PARENT"))?
        };
        Ok(self.object(id))
    }
}
type FixtureOwner = AttachmentOwner<FixtureRegistry, Store>;
fn owner(store: &Store, registry: &FixtureRegistry, health: &HealthFixture) -> FixtureOwner {
    AttachmentOwner::observe(registry.clone(), store.clone(), hint(), health, end()).unwrap()
}

#[test]
fn attachment_borrowed_witness_drop_never_revokes_and_same_id_rebind_invalidates_original_generation() {
    let store = Store::new();
    let instance = store.instance(10);
    let generation = store.state.borrow_mut().bind(instance).unwrap();
    let old = LocalSelectionWitness::capture(&store.state.borrow()).unwrap();
    let borrowed = LocalSelectionWitness::capture(&store.state.borrow()).unwrap();
    drop(borrowed);
    assert!(old.require(&store.state.borrow()).is_ok());
    assert!(store.state.borrow_mut().release(generation));
    let instance = store.instance(10);
    store.state.borrow_mut().bind(instance).unwrap();
    assert!(old.require(&store.state.borrow()).is_err());
    assert!(LocalSelectionWitness::capture(&store.state.borrow()).is_ok());
    assert_eq!(store.wipes.get(), 0);
}

#[test]
fn attachment_witness_refuses_missing_pair_monitor_loss_and_replacement_monitor() {
    let store = Store::new();
    assert!(LocalSelectionWitness::capture(&store.state.borrow()).is_err());
    let pair = vec![store.instance(10), store.instance(11)];
    let generation = store.state.borrow_mut().bind_set(pair).unwrap();
    assert!(LocalSelectionWitness::capture(&store.state.borrow()).is_err());
    store.state.borrow_mut().release(generation);
    let instance = store.instance(10);
    store.state.borrow_mut().bind(instance).unwrap();
    let old = LocalSelectionWitness::capture(&store.state.borrow()).unwrap();
    let monitor = store.state.borrow().monitor_generation;
    store.state.borrow_mut().monitor_lost(monitor);
    assert!(old.require(&store.state.borrow()).is_err());
    store.state.borrow_mut().monitor_started().unwrap();
    let instance = store.instance(10);
    store.state.borrow_mut().bind(instance).unwrap();
    assert!(old.require(&store.state.borrow()).is_err());
}

#[test]
fn attachment_wire_hint_has_no_epoch_generation_or_authority_and_debug_redacts_id() {
    let wire = serde_json::to_value(hint()).unwrap();
    assert_eq!(wire.as_object().unwrap().len(), 2);
    assert_eq!(wire["version"], 1);
    assert_eq!(wire["service_registry_id"], 10);
    assert!(serde_json::from_str::<AttachmentHint>(r#"{"version":1,"service_registry_id":10,"epoch":7}"#).is_err());
    assert!(serde_json::from_str::<AttachmentHint>(r#"{"version":1,"version":1,"service_registry_id":10}"#).is_err());
    for bad in [AttachmentHint { version: 2, ..hint() }, AttachmentHint { service_registry_id: 0, ..hint() }] {
        assert!(bad.validate().is_err());
    }
    assert!(!format!("{:?}", hint()).contains("10"));
}

#[test]
fn attachment_root_uses_local_epoch_retains_one_original_and_drop_revokes_once() {
    let store = Store::new();
    store.state.borrow_mut().event_epoch = 37;
    let registry = FixtureRegistry::new(store.clone());
    let health = HealthFixture::default();
    let mut selected = owner(&store, &registry, &health);
    assert_eq!(store.state.borrow().selected.as_ref().unwrap().1[0].observed_event_epoch, 37);
    assert_eq!(registry.data.borrow().live.get(), 1);
    assert_eq!(registry.data.borrow().lookups, 2);
    selected.require_current(hint(), &health, end()).unwrap();
    assert!(health.calls.get() >= 6);
    assert_eq!(registry.data.borrow().live.get(), 1);
    drop(selected);
    assert!(store.state.borrow().selected.is_none());
    assert_eq!(store.wipes.get(), 1);
    assert_eq!(registry.data.borrow().live.get(), 0);
}

#[test]
fn attachment_walk_refuses_wrong_id_class_parent_error_and_unreached_actual_root_without_leaks() {
    for mode in 0..5 {
        let store = Store::new();
        let registry = FixtureRegistry::new(store.clone());
        {
            let mut data = registry.data.borrow_mut();
            match mode {
                0 => data.lookup_id = 11,
                1 => data.usb = false,
                2 => data.parent_error = Some(20),
                3 => data.root_id = 99,
                _ => data.identity_error = Some(20),
            }
        }
        assert!(AttachmentOwner::observe(registry.clone(), store.clone(), hint(), &HealthFixture::default(), end()).is_err());
        assert_eq!(registry.data.borrow().live.get(), 0);
        assert!(store.state.borrow().selected.is_none());
        assert_eq!(store.wipes.get(), 0);
    }
}

#[test]
fn attachment_walk_cycle_zero_and_depth_limit_refuse_and_release_every_transient() {
    for mode in 0..3 {
        let store = Store::new();
        let registry = FixtureRegistry::new(store.clone());
        {
            let mut data = registry.data.borrow_mut();
            match mode {
                0 => { data.parents.insert(20, 10); },
                1 => { data.parents.insert(20, 0); },
                _ => { for id in 20..90 { data.parents.insert(id, id + 1); } },
            }
        }
        assert!(AttachmentOwner::observe(registry.clone(), store.clone(), hint(), &HealthFixture::default(), end()).is_err());
        assert_eq!(registry.data.borrow().live.get(), 0);
    }
}

#[test]
fn attachment_termination_between_local_epoch_capture_and_root_bind_never_acquires_guard() {
    let store = Store::new();
    let registry = FixtureRegistry::new(store.clone());
    registry.data.borrow_mut().terminate_at = Some((1, vec![Some(10)]));
    assert!(AttachmentOwner::observe(registry.clone(), store.clone(), hint(), &HealthFixture::default(), end()).is_err());
    assert_eq!(registry.data.borrow().live.get(), 0);
    assert!(store.state.borrow().selected.is_none());
    assert_eq!(store.wipes.get(), 0);
}

#[test]
fn attachment_unrelated_loss_preserves_owner_but_selected_ancestor_and_unknown_loss_poison() {
    for ids in [vec![Some(10)], vec![Some(20)], vec![None]] {
        let store = Store::new();
        let registry = FixtureRegistry::new(store.clone());
        let health = HealthFixture::default();
        let mut selected = owner(&store, &registry, &health);
        assert!(!store.state.borrow_mut().terminate(&[Some(999)]));
        selected.require_current(hint(), &health, end()).unwrap();
        assert!(store.state.borrow_mut().terminate(&ids));
        assert!(selected.require_current(hint(), &health, end()).is_err());
        assert!(selected.poisoned);
        assert!(selected.guard.is_none());
        assert!(selected.require_current(hint(), &health, end()).unwrap_err().is("ATTACHMENT_OWNER_POISONED"));
        assert_eq!(registry.data.borrow().live.get(), 1);
        drop(selected);
        assert_eq!(registry.data.borrow().live.get(), 0);
    }
}

#[test]
fn attachment_native_replacement_ancestry_and_hint_changes_irreversibly_release_owned_guard() {
    for mode in 0..3 {
        let store = Store::new();
        let registry = FixtureRegistry::new(store.clone());
        let health = HealthFixture::default();
        let mut selected = owner(&store, &registry, &health);
        let mut next_hint = hint();
        match mode {
            0 => registry.data.borrow_mut().incarnation += 1,
            1 => { registry.data.borrow_mut().parents.insert(10, 21); registry.data.borrow_mut().parents.insert(21, 1); },
            _ => next_hint.service_registry_id = 11,
        }
        assert!(selected.require_current(next_hint, &health, end()).is_err());
        registry.data.borrow_mut().incarnation = 1;
        assert_eq!(store.wipes.get(), 1);
        assert!(selected.require_current(hint(), &health, end()).is_err());
        drop(selected);
        assert_eq!(store.wipes.get(), 1);
        assert_eq!(registry.data.borrow().live.get(), 0);
    }
}

#[test]
fn attachment_fresh_health_failure_before_or_after_native_walk_poison_without_revival() {
    for offset in [1, 2] {
        let store = Store::new();
        let registry = FixtureRegistry::new(store.clone());
        let health = HealthFixture::default();
        let mut selected = owner(&store, &registry, &health);
        health.fail_at.set(health.calls.get() + offset);
        assert!(selected.require_current(hint(), &health, end()).is_err());
        health.fail_at.set(0);
        assert!(selected.require_current(hint(), &health, end()).is_err());
        assert_eq!(store.wipes.get(), 1);
    }
}

#[test]
fn attachment_obsolete_root_guard_never_revokes_new_selection_and_new_monitor_never_repairs_owner() {
    let store = Store::new();
    let registry = FixtureRegistry::new(store.clone());
    let health = HealthFixture::default();
    let mut selected = owner(&store, &registry, &health);
    let old_monitor = store.state.borrow().monitor_generation;
    assert!(store.state.borrow_mut().monitor_lost(old_monitor));
    store.state.borrow_mut().monitor_started().unwrap();
    let replacement = store.instance(10);
    let generation = store.state.borrow_mut().bind(replacement).unwrap();
    assert!(selected.require_current(hint(), &health, end()).is_err());
    assert!(store.state.borrow().current(generation, 1));
    drop(selected);
    assert!(store.state.borrow().current(generation, 1));
    assert_eq!(store.wipes.get(), 0);
}

#[test]
fn attachment_same_monitor_same_id_rebind_cannot_replace_root_original_guard() {
    let store = Store::new();
    let registry = FixtureRegistry::new(store.clone());
    let health = HealthFixture::default();
    let mut selected = owner(&store, &registry, &health);
    let original_generation = store.state.borrow().selected.as_ref().unwrap().0;
    assert!(store.state.borrow_mut().release(original_generation));
    let replacement = store.instance(10);
    let generation = store.state.borrow_mut().bind(replacement).unwrap();
    assert!(selected.require_current(hint(), &health, end()).is_err());
    assert!(store.state.borrow().current(generation, 1));
    assert_eq!(store.wipes.get(), 0);
}

#[test]
fn attachment_existing_singleton_or_pair_is_never_adopted_or_revoked_by_new_observer() {
    for count in [1, 2] {
        let store = Store::new();
        let registry = FixtureRegistry::new(store.clone());
        let instances = (0..count).map(|n| store.instance(10 + n)).collect();
        let generation = store.state.borrow_mut().bind_set(instances).unwrap();
        assert!(AttachmentOwner::observe(registry.clone(), store.clone(), hint(), &HealthFixture::default(), end()).is_err());
        assert!(store.state.borrow().current(generation, count as usize));
        assert_eq!(registry.data.borrow().live.get(), 0);
        assert_eq!(store.wipes.get(), 0);
    }
}

#[test]
fn attachment_deadline_and_partial_startup_failures_retain_no_guard_or_native_rights() {
    for fail_at in 0..=4 {
        let store = Store::new();
        let registry = FixtureRegistry::new(store.clone());
        let health = HealthFixture::default();
        health.fail_at.set(fail_at);
        let deadline = if fail_at == 0 { Instant::now() } else { end() };
        assert!(AttachmentOwner::observe(registry.clone(), store.clone(), hint(), &health, deadline).is_err());
        assert!(store.state.borrow().selected.is_none());
        assert_eq!(registry.data.borrow().live.get(), 0);
        assert_eq!(store.wipes.get(), usize::from(fail_at >= 3));
    }
}

#[test]
fn attachment_cancellation_before_observe_prevents_native_work_and_late_bind() {
    let store = Store::new();
    let registry = FixtureRegistry::new(store.clone());
    let cancellation = RootAttachmentCancellation::new();
    cancellation.cancel_with(|_| panic!("pending token had authority"));
    assert!(AttachmentOwner::observe_cancellable(registry.clone(), store.clone(), hint(), &HealthFixture::default(), end(), &cancellation).is_err());
    assert_eq!(registry.data.borrow().lookups, 0);
    assert!(store.state.borrow().selected.is_none());
    assert!(cancellation.require_pending().is_err());
}

#[test]
fn attachment_cancellation_all_observation_failures_consume_same_token() {
    for mode in 0..7 {
        let store = Store::new();
        let registry = FixtureRegistry::new(store.clone());
        let health = HealthFixture::default();
        if mode <= 4 { health.fail_at.set(mode); }
        if mode == 5 { registry.data.borrow_mut().lookup_id = 11; }
        if mode == 6 { store.state.borrow_mut().monitor_lost(1); }
        let cancellation = RootAttachmentCancellation::new();
        let deadline = if mode == 0 { Instant::now() } else { end() };
        assert!(AttachmentOwner::observe_cancellable(registry.clone(), store.clone(), hint(), &health, deadline, &cancellation).is_err());
        assert!(cancellation.require_pending().is_err());
        assert!(matches!(*cancellation.0.lock().unwrap(), CancellationState::Cancelled));
        assert!(store.state.borrow().selected.is_none());
        assert_eq!(registry.data.borrow().live.get(), 0);
    }
}

#[test]
fn attachment_cancellation_reentrant_callback_holds_neither_metadata_nor_topology_lock() {
    let store = Store::new();
    let registry = FixtureRegistry::new(store.clone());
    let cancellation = RootAttachmentCancellation::new();
    let mut selected = AttachmentOwner::observe_cancellable(registry, store.clone(), hint(), &HealthFixture::default(), end(), &cancellation).unwrap();
    cancellation.cancel_with(|generation| {
        assert!(cancellation.0.try_lock().is_ok());
        assert!(store.state.try_borrow_mut().is_ok());
        cancellation.cancel_with(|_| panic!("reentrant cancellation repeated release"));
        store.revoke(generation);
    });
    assert!(store.state.borrow().selected.is_none());
    assert_eq!(store.wipes.get(), 1);
    assert!(selected.require_current(hint(), &HealthFixture::default(), end()).is_err());
    drop(selected);
    assert_eq!(store.wipes.get(), 1);
}

#[test]
fn attachment_cancellation_stale_token_cannot_revoke_same_id_replacement() {
    let store = Store::new();
    let registry = FixtureRegistry::new(store.clone());
    let cancellation = RootAttachmentCancellation::new();
    let selected = AttachmentOwner::observe_cancellable(registry, store.clone(), hint(), &HealthFixture::default(), end(), &cancellation).unwrap();
    let original = store.state.borrow().selected.as_ref().unwrap().0;
    assert!(store.state.borrow_mut().release(original));
    let replacement = store.instance(10);
    let replacement = store.state.borrow_mut().bind(replacement).unwrap();
    cancellation.cancel_with(|generation| { assert_eq!(generation, original); store.revoke(generation); });
    drop(selected);
    assert!(store.state.borrow().current(replacement, 1));
    assert_eq!(store.wipes.get(), 0);
}

#[test]
fn attachment_cancellation_clone_drop_preserves_owner_but_owner_drop_is_terminal() {
    let store = Store::new();
    let registry = FixtureRegistry::new(store.clone());
    let cancellation = RootAttachmentCancellation::new();
    let selected = AttachmentOwner::observe_cancellable(registry.clone(), store.clone(), hint(), &HealthFixture::default(), end(), &cancellation).unwrap();
    drop(cancellation.clone());
    assert!(store.state.borrow().selected.is_some());
    drop(selected);
    assert!(store.state.borrow().selected.is_none());
    assert_eq!(store.wipes.get(), 1);
    assert!(AttachmentOwner::observe_cancellable(registry, store.clone(), hint(), &HealthFixture::default(), end(), &cancellation).is_err());
    assert_eq!(store.wipes.get(), 1);
}

#[test]
fn attachment_cancellation_poisoned_pending_and_bound_metadata_never_revive() {
    for bound in [false, true] {
        let store = Store::new();
        let registry = FixtureRegistry::new(store.clone());
        let cancellation = RootAttachmentCancellation::new();
        let selected = bound.then(|| AttachmentOwner::observe_cancellable(registry, store.clone(), hint(), &HealthFixture::default(), end(), &cancellation).unwrap());
        let result = std::panic::catch_unwind(|| {
            let _guard = cancellation.0.lock().unwrap();
            panic!("fixture cancellation metadata poison");
        });
        assert!(result.is_err());
        assert!(cancellation.require_pending().is_err());
        cancellation.cancel_with(|generation| {
            assert!(cancellation.0.try_lock().is_err_and(|error| matches!(error, std::sync::TryLockError::Poisoned(_))));
            store.revoke(generation);
        });
        cancellation.cancel_with(|_| panic!("poisoned metadata released twice"));
        drop(selected);
        assert!(store.state.borrow().selected.is_none());
        assert_eq!(store.wipes.get(), usize::from(bound));
        assert!(matches!(*cancellation.0.lock().unwrap_err().into_inner(), CancellationState::Cancelled));
    }
}

#[test]
fn attachment_cancellation_caught_observation_unwind_consumes_pending_token() {
    struct Panics;
    impl Health for Panics { fn observe(&self, _: Instant) -> EnclaveResult<()> { panic!("fixture health panic"); } }
    let store = Store::new();
    let registry = FixtureRegistry::new(store.clone());
    let cancellation = RootAttachmentCancellation::new();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = AttachmentOwner::observe_cancellable(registry, store.clone(), hint(), &Panics, end(), &cancellation);
    })).is_err());
    assert!(cancellation.require_pending().is_err());
    assert!(store.state.borrow().selected.is_none());
}

// Thread-safe fixtures still use the actual UsbSelection state machine. Native
// objects stay on the observer thread while the independent canceller runs.
#[derive(Clone)]
struct ThreadStore { state: Arc<Mutex<UsbSelection>>, wipes: Arc<std::sync::atomic::AtomicUsize> }
impl ThreadStore {
    fn new() -> Self {
        let mut state = UsbSelection::default();
        state.monitor_started().unwrap();
        Self { state: Arc::new(Mutex::new(state)), wipes: Arc::new(std::sync::atomic::AtomicUsize::new(0)) }
    }
}
struct ThreadGuard { store: ThreadStore, generation: u64 }
impl Drop for ThreadGuard { fn drop(&mut self) { self.store.revoke(self.generation); } }
impl SelectionStore for ThreadStore {
    type Guard = ThreadGuard;
    fn observation(&self) -> EnclaveResult<(u64, UsbObservationEpoch)> {
        let state = self.state.lock().unwrap();
        monitor_current(&state, state.monitor_generation)?;
        Ok((state.monitor_generation, UsbObservationEpoch(state.event_epoch)))
    }
    fn bind_generation(&self, monitor: u64, instance: SelectedUsbInstance) -> EnclaveResult<u64> {
        let mut state = self.state.lock().unwrap();
        monitor_current(&state, monitor)?;
        state.bind(instance)
    }
    fn own_generation(&self, generation: u64) -> ThreadGuard { ThreadGuard { store: self.clone(), generation } }
    fn generation(&self, guard: &ThreadGuard) -> u64 { guard.generation }
    fn revoke(&self, generation: u64) {
        let invalidate = self.state.lock().unwrap().release(generation);
        if invalidate {
            assert!(self.state.try_lock().is_ok());
            self.wipes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    fn require(&self, monitor: u64, guard: &ThreadGuard) -> EnclaveResult<()> {
        let state = self.state.lock().unwrap();
        monitor_current(&state, monitor)?;
        state.require(Some(guard.generation), 1)
    }
}
struct GatedRegistry {
    inner: FixtureRegistry, calls: usize, at: usize,
    entered: std::sync::mpsc::SyncSender<()>, resume: std::sync::mpsc::Receiver<()>,
}
impl Registry for GatedRegistry {
    type Object = Object;
    fn root(&mut self) -> EnclaveResult<Object> { self.inner.root() }
    fn lookup(&mut self, id: u64) -> EnclaveResult<Object> {
        self.calls += 1;
        if self.calls == self.at {
            self.entered.send(()).unwrap();
            self.resume.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        self.inner.lookup(id)
    }
    fn identity(&mut self, object: &Object) -> EnclaveResult<u64> { self.inner.identity(object) }
    fn is_usb(&mut self, object: &Object) -> bool { self.inner.is_usb(object) }
    fn equal(&mut self, left: &Object, right: &Object) -> bool { self.inner.equal(left, right) }
    fn parent(&mut self, object: &Object) -> EnclaveResult<Object> { self.inner.parent(object) }
}

#[test]
fn attachment_cancellation_independent_of_blocked_native_observe_and_revalidation() {
    for at in [1, 2, 3] {
        let store = ThreadStore::new();
        let cancellation = RootAttachmentCancellation::new();
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(0);
        let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(0);
        let registry = GatedRegistry { inner: FixtureRegistry::new(Store::new()), calls: 0, at,
            entered: entered_tx, resume: resume_rx };
        let worker_store = store.clone();
        let worker_token = cancellation.clone();
        let worker = std::thread::spawn(move || {
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            worker_token.cancel_with(|generation| {
                assert!(worker_token.0.try_lock().is_ok());
                worker_store.revoke(generation);
            });
            // Check completed revocation while the registry remains blocked.
            assert!(worker_store.state.lock().unwrap().selected.is_none());
            assert_eq!(worker_store.wipes.load(std::sync::atomic::Ordering::SeqCst), usize::from(at > 1));
            resume_tx.send(()).unwrap();
        });
        let health = HealthFixture::default();
        let result = AttachmentOwner::observe_cancellable(registry, store.clone(), hint(), &health, end(), &cancellation);
        if at == 3 {
            let mut selected = result.unwrap();
            assert!(selected.require_current(hint(), &health, end()).is_err());
        } else { assert!(result.is_err()); }
        worker.join().unwrap();
        assert!(store.state.lock().unwrap().selected.is_none());
        assert!(cancellation.require_pending().is_err());
    }
}
