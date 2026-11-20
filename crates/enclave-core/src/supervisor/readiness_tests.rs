//! Private SOFTWARE wire fixtures; no production selection, bind or native owner.
use super::*;
use crate::ipc::FrameIoLimits;
fn binding()->Binding {Binding {target_id:"fixture".into(),descriptor_sha256:"a".repeat(64),profile:Profile::L2,signing:DeploymentSigningMode::LocalPins}}
fn observation(request:Request)->Observation {Observation {version:1,kind:"mcpmac-selected-supervisor-observation".into(),challenge:request.challenge,
    binding:binding(),instance:[7;32],started_boot_ns:crate::clock::boot_clock_ns(),ended_boot_ns:crate::clock::boot_clock_ns(),
    terms:REQUIRED.into_iter().map(|term|(term,Outcome::Observed)).collect(),retained_errors:Vec::new()}}
fn limits()->FrameIoLimits {FrameIoLimits {max_frame:FRAME,frame_deadline:Duration::from_secs(2),idle_timeout:Duration::from_secs(2)}}
// The existing wire fixtures now execute the SAME guarded absolute transport
// and strict observation engine as Native, with explicitly synthetic context.
fn exchange(stream:&mut Option<UnixStream>,binding:&Binding,instance:&mut Option<[u8;32]>,end:Instant)->EnclaveResult<()> {
    let valid=AtomicBool::new(true);let calls=std::sync::atomic::AtomicUsize::new(0);let failed=AtomicBool::new(false);
    let guard=SelectedReadinessIoGuard::fixture(end,&valid,&calls,&failed);
    let mut operation=ReadinessOperation {guard,stream,armed:true};
    exchange_owned(&mut operation,binding,instance,end)?;
    operation.current()?;operation.guard.complete_probe()?;operation.complete();Ok(())
}
fn fixture(change:impl FnOnce(&mut Observation)+Send+'static)->EnclaveResult<()> {
    let (client,mut server)=UnixStream::pair().unwrap();let mut client=Some(client);
    let worker=std::thread::spawn(move||{
        let request=strict_decode::<Request>(&ipc::read_frame_timed(&mut server,&limits()).unwrap()).unwrap();
        let mut response=observation(request);change(&mut response);
        ipc::write_frame_timed(&mut server,&ipc::to_cbor(&ipc::Reply::Ok(response)).unwrap(),&limits()).unwrap();
    });
    let result=exchange(&mut client,&binding(),&mut None,Instant::now()+Duration::from_secs(2));worker.join().unwrap();result
}
#[test]
fn exact_fresh_fixture_exchange_accepts_only_complete_required_conjunction() {
    fixture(|_|{}).unwrap();
    for term in REQUIRED {fixture(move|response|{response.terms.insert(term,Outcome::Missing);}).unwrap_err();}
    fixture(|response|response.retained_errors.push("ORIGINAL_CHANGED".into())).unwrap_err();
}
#[test]
fn wrong_version_challenge_identity_profile_and_clock_are_refusals() {
    for variant in 0..8 {assert!(fixture(move|response|match variant {
        0=>response.version=2,1=>response.challenge[0]^=1,2=>response.binding.target_id.push('x'),
        3=>response.binding.descriptor_sha256="b".repeat(64),4=>response.binding.profile=Profile::L3,
        5=>response.binding.signing=DeploymentSigningMode::TeamId,6=>response.instance=[0;32],_=>response.ended_boot_ns=u64::MAX,
    }).unwrap_err().is("SUPERVISOR_DEPENDENCY_BINDING"));}
}
#[test]
fn same_connection_cannot_switch_live_instance() {
    let (client,mut server)=UnixStream::pair().unwrap();let mut client=Some(client);
    let worker=std::thread::spawn(move||{
        for i in 0..2 {
            let request=strict_decode::<Request>(&ipc::read_frame_timed(&mut server,&limits()).unwrap()).unwrap();
            let mut response=observation(request);if i==1 {response.instance=[8;32];}
            ipc::write_frame_timed(&mut server,&ipc::to_cbor(&ipc::Reply::Ok(response)).unwrap(),&limits()).unwrap();
        }
    });
    let mut instance=None;exchange(&mut client,&binding(),&mut instance,Instant::now()+PROBE).unwrap();
    assert!(exchange(&mut client,&binding(),&mut instance,Instant::now()+PROBE).unwrap_err().is("SUPERVISOR_DEPENDENCY_BINDING"));worker.join().unwrap();
}
#[test]
fn same_connection_cannot_reuse_an_old_challenge_observation() {
    let (client,mut server)=UnixStream::pair().unwrap();let mut client=Some(client);
    let worker=std::thread::spawn(move||{
        let first=strict_decode::<Request>(&ipc::read_frame_timed(&mut server,&limits()).unwrap()).unwrap();
        let response=ipc::to_cbor(&ipc::Reply::Ok(observation(first))).unwrap();
        ipc::write_frame_timed(&mut server,&response,&limits()).unwrap();
        let _next=strict_decode::<Request>(&ipc::read_frame_timed(&mut server,&limits()).unwrap()).unwrap();
        ipc::write_frame_timed(&mut server,&response,&limits()).unwrap();
    });
    let mut instance=None;exchange(&mut client,&binding(),&mut instance,Instant::now()+PROBE).unwrap();
    assert!(exchange(&mut client,&binding(),&mut instance,Instant::now()+PROBE).unwrap_err().is("SUPERVISOR_DEPENDENCY_BINDING"));
    worker.join().unwrap();
}
#[test]
fn strict_request_schema_rejects_extra_duplicate_nested_and_trailing_cbor() {
    use ciborium::value::Value;
    let request=Request {version:1,challenge:[1;32]};let bytes=ipc::to_cbor(&request).unwrap();
    strict_decode::<Request>(&bytes).unwrap();let mut trailing=bytes.clone();trailing.push(0);
    assert!(strict_decode::<Request>(&trailing).unwrap_err().is("SUPERVISOR_DEPENDENCY_TRAILING_DATA"));
    let mut value:Value=ciborium::from_reader(bytes.as_slice()).unwrap();
    if let Value::Map(entries)=&mut value {entries.push((Value::Text("skip_pf".into()),Value::Bool(true)));}
    assert!(strict_decode::<Request>(&ipc::to_cbor(&value).unwrap()).is_err());
    let mut value:Value=ciborium::from_reader(bytes.as_slice()).unwrap();
    if let Value::Map(entries)=&mut value {entries.push(entries[0].clone());}
    assert!(strict_decode::<Request>(&ipc::to_cbor(&value).unwrap()).is_err());
    let duplicate=Value::Map(vec![(Value::Text("a".into()),Value::Map(vec![(Value::Text("x".into()),Value::Bool(true)),(Value::Text("x".into()),Value::Bool(false))]))]);
    assert!(strict_decode::<Value>(&ipc::to_cbor(&duplicate).unwrap()).is_err());
    assert!(strict_decode::<Request>(&vec![0;FRAME+1]).is_err());
}
#[test]
fn whole_exchange_endpoint_is_not_renewed_by_each_frame() {
    let (client,_server)=UnixStream::pair().unwrap();let mut client=Some(client);
    let now=Instant::now();let result=exchange(&mut client,&binding(),&mut None,now+Duration::from_millis(30));
    assert!(result.is_err());assert!(now.elapsed()<Duration::from_secs(1));
}
#[test]
fn expired_exchange_emits_no_request_bytes() {
    use std::io::Read;
    let (client,mut server)=UnixStream::pair().unwrap();let mut client=Some(client);
    assert!(exchange(&mut client,&binding(),&mut None,Instant::now()).is_err());
    server.set_nonblocking(true).unwrap();let mut byte=[0u8;1];
    assert_eq!(server.read(&mut byte).unwrap(),0,"terminal refusal closes the original without request bytes");
}
#[test]
fn descriptive_all_observed_fixture_cannot_construct_a_native_client() {
    let response=observation(Request {version:1,challenge:[1;32]});assert!(complete(&response));
    if !cfg!(target_os="macos") || ipc::geteuid()!=DaemonId::CustodyVault.uid() {
        assert!(SelectedReadinessClient::connect_custody(Instant::now()+PROBE).is_err());
    }
}

fn root_peer_fixture()->ipc::PeerCredentials {
    let mut peer=ipc::PeerCredentials::local(0,0);peer.pid=Some(111);peer.audit_token=Some([7;8]);
    peer.code_identity=Some(codesign::CodeIdentity {identifier:codesign::CTL_IDENTIFIER.into(),
        team_id:String::new(),cdhash:"a".repeat(40)});peer
}

#[test]
fn original_root_peer_and_same_socket_bracket_each_operation_without_rebinding() {
    let original=root_peer_fixture();let mut pin=RootPeerPin::new(original.clone()).unwrap();
    let mut socket=Vec::new();let reads=std::cell::Cell::new(0);
    for _ in 0..2 {
        pin.checked_with(&mut socket,Instant::now()+PROBE,|socket,_|{
            reads.set(reads.get()+1);assert!(socket.len()<=2);Ok(original.clone())
        },|socket| {socket.push("original-operation");Ok(())}).unwrap();
    }
    assert_eq!(reads.get(),4);assert_eq!(socket,["original-operation";2]);
    assert_eq!(pin.original,original);assert!(!pin.poisoned);
}

#[test]
fn root_peer_token_code_uid_and_missing_authentication_refuse_before_operation() {
    for variant in 0..8 {
        let original=root_peer_fixture();let mut pin=RootPeerPin::new(original.clone()).unwrap();
        let mut current=original.clone();match variant {
            0=>current.audit_token.as_mut().unwrap()[7]^=1,
            1=>current.code_identity.as_mut().unwrap().cdhash="b".repeat(40),
            2=>current.uid=703,3=>current.gid=703,4=>current.audit_token=None,
            5=>current.code_identity=None,6=>current.tls_channel_binding=Some([1;32]),
            _=>current.code_identity.as_mut().unwrap().identifier.push('x'),
        }
        assert!(pin.checked_with(&mut (),Instant::now()+PROBE,|_,_|Ok(current.clone()),
            |_|->EnclaveResult<()> {panic!("changed root peer reached operation")}).is_err());
        assert!(pin.poisoned);assert_eq!(pin.original,original);
        assert!(pin.checked_with(&mut (),Instant::now()+PROBE,|_,_|panic!("poison reread peer"),
            |_|->EnclaveResult<()> {panic!("poison repeated operation")}).is_err());
    }
    for variant in 0..3 {
        let mut peer=root_peer_fixture();match variant {0=>peer.uid=703,1=>peer.audit_token=None,_=>peer.code_identity=None}
        assert!(RootPeerPin::new(peer).is_err());
    }
}

#[test]
fn late_peer_change_error_expiry_and_unwind_are_terminal_without_repeating_original() {
    for variant in 0..4 {
        let original=root_peer_fixture();let mut pin=RootPeerPin::new(original.clone()).unwrap();
        let mut operations=0;let reads=std::cell::Cell::new(0);
        let end=Instant::now()+if variant==2 {Duration::from_millis(20)}else{PROBE};
        let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
            pin.checked_with(&mut operations,end,|_,_|{
                let n=reads.get();reads.set(n+1);let mut peer=original.clone();
                if n==1 {peer.audit_token.as_mut().unwrap()[0]^=1;}Ok(peer)
            },|operations| {
                *operations+=1;
                if variant==1 {fail!(EIO,"FIXTURE_OPERATION_FAILED");}
                if variant==2 {while Instant::now()<end {std::thread::yield_now();}}
                if variant==3 {panic!("fixture original operation unwind");}Ok(())
            })));
        assert!(result.is_err() || result.unwrap().is_err());assert!(pin.poisoned);
        assert_eq!(operations,1);assert_eq!(pin.original,original);
        assert!(pin.checked_with(&mut operations,Instant::now()+PROBE,
            |_,_|panic!("late failure recaptured peer"),|_|->EnclaveResult<()> {panic!("late failure repeated original")}).is_err());
    }
}

struct AssignmentFixture {events:Arc<Mutex<Vec<&'static str>>>,reads:usize,fail_at:usize}
impl CurrentTaskAssignment for AssignmentFixture {
    fn observe_current(&mut self,end:Instant)->EnclaveResult<()> {
        within(end)?;self.reads+=1;self.events.lock().unwrap().push("readback");
        if self.reads==self.fail_at {fail!(EACCES,"FIXTURE_ASSIGNMENT_LOST");}Ok(())
    }
}
impl Drop for AssignmentFixture {fn drop(&mut self){self.events.lock().unwrap().push("drop-original");}}

#[test]
fn assignment_requires_successful_initial_probe_and_never_revives_after_initial_failure() {
    let mut state=TaskAssignment::<AssignmentFixture>::new();
    assert!(state.assign(Instant::now()+PROBE,|_|panic!("assignment before initial observation")).is_err());
    assert!(state.probe(Instant::now()+PROBE,||panic!("poisoned operation revived")).is_err());
    let mut state=TaskAssignment::<AssignmentFixture>::new();
    assert!(state.probe(Instant::now()+PROBE,||Err(err!(EACCES,"FIXTURE_INITIAL_REFUSAL"))).is_err());
    assert!(state.assign(Instant::now()+PROBE,|_|panic!("failed initial observation assigned")).is_err());
    assert!(state.owner.is_none());
}

#[test]
fn second_unassigned_probe_and_repeated_assignment_never_repeat_exchange_or_constructor() {
    let mut state=TaskAssignment::<AssignmentFixture>::new();
    state.probe(Instant::now()+PROBE,||Ok(())).unwrap();
    assert!(state.probe(Instant::now()+PROBE,||panic!("unassigned repeated exchange")).is_err());
    assert!(state.assign(Instant::now()+PROBE,|_|panic!("poisoned unassigned operation assigned")).is_err());
    let events=Arc::new(Mutex::new(Vec::new()));let mut state=TaskAssignment::new();
    state.probe(Instant::now()+PROBE,||Ok(())).unwrap();
    state.assign(Instant::now()+PROBE,|_|Ok(AssignmentFixture {events:events.clone(),reads:0,fail_at:0})).unwrap();
    assert!(state.assign(Instant::now()+PROBE,|_|panic!("original assignment replaced")).is_err());
    assert!(events.lock().unwrap().is_empty());assert!(state.owner.is_some());
    drop(state);assert_eq!(*events.lock().unwrap(),["drop-original"]);
}

#[test]
fn assigned_probe_reads_same_owner_before_and_after_exchange_and_retains_it_on_late_loss() {
    let events=Arc::new(Mutex::new(Vec::new()));let mut state=TaskAssignment::new();
    state.probe(Instant::now()+PROBE,||Ok(())).unwrap();
    state.assign(Instant::now()+PROBE,|_|Ok(AssignmentFixture {events:events.clone(),reads:0,fail_at:4})).unwrap();
    let original=state.owner.as_ref().unwrap() as *const AssignmentFixture;
    state.probe(Instant::now()+PROBE,||{events.lock().unwrap().push("exchange");Ok(())}).unwrap();
    assert!(state.probe(Instant::now()+PROBE,||{events.lock().unwrap().push("exchange");Ok(())}).unwrap_err().is("FIXTURE_ASSIGNMENT_LOST"));
    assert_eq!(state.owner.as_ref().unwrap() as *const AssignmentFixture,original);
    assert_eq!(*events.lock().unwrap(),["readback","exchange","readback","readback","exchange","readback"]);
    assert!(state.probe(Instant::now()+PROBE,||panic!("late refusal revived")).is_err());
    assert!(state.assign(Instant::now()+PROBE,|_|panic!("late refusal reassigned")).is_err());
    assert_eq!(events.lock().unwrap().len(),6);drop(state);
    assert_eq!(events.lock().unwrap().last(),Some(&"drop-original"));
}

// SOFTWARE tests of the production lifetime algorithm. This private trait is
// never a constructor for SelectedOwnerSession or any native readiness owner.
struct SessionFixture {
    end:Instant,live:Arc<AtomicBool>,events:Arc<Mutex<Vec<&'static str>>>,
}
impl SessionDependency for SessionFixture {
    fn current(&self)->EnclaveResult<()> {
        self.events.lock().unwrap().push("current");
        if !self.live.load(Ordering::SeqCst) {fail!(EACCES,"FIXTURE_SESSION_REVOKED");}Ok(())
    }
    fn revoke(&self) {self.events.lock().unwrap().push("revoke");self.live.store(false,Ordering::SeqCst);}
    fn original_end(&self)->Instant {self.end}
}
impl Drop for SessionFixture {fn drop(&mut self){self.events.lock().unwrap().push("drop-session");}}
fn session_fixture()->(SessionLifetime<SessionFixture>,Arc<Mutex<Vec<&'static str>>>) {
    let events=Arc::new(Mutex::new(Vec::new()));
    (SessionLifetime::new(SessionFixture {end:Instant::now()+PROBE,live:Arc::new(AtomicBool::new(true)),events:events.clone()},
        Arc::new(AtomicBool::new(false))),events)
}
#[test]
fn same_session_lifetime_wraps_original_operation_before_and_after_and_revokes_before_drop() {
    let (owner,events)=session_fixture();
    owner.checked(||{events.lock().unwrap().push("original-operation");Ok(())}).unwrap();
    assert_eq!(*events.lock().unwrap(),["current","original-operation","current"]);
    drop(owner);assert_eq!(*events.lock().unwrap(),["current","original-operation","current","revoke","drop-session"]);
}
#[test]
fn late_session_loss_is_terminal_and_never_repeats_original_operation_after_stop_flag_reset() {
    let (owner,events)=session_fixture();
    assert!(owner.checked(||{owner.session.live.store(false,Ordering::SeqCst);Ok(())}).unwrap_err().is("FIXTURE_SESSION_REVOKED"));
    assert!(owner.stop.load(Ordering::SeqCst));
    owner.stop.store(false,Ordering::SeqCst);
    assert!(owner.checked::<()>(||panic!("revoked original may never run again")).is_err());
    assert_eq!(events.lock().unwrap().iter().filter(|event|**event=="current").count(),3);
}
#[test]
fn original_operation_failure_revokes_session_before_any_later_cleanup_or_operation() {
    let (owner,events)=session_fixture();
    assert!(owner.checked(||Err::<(),_>(err!(EIO,"FIXTURE_ORIGINAL_FAILURE"))).unwrap_err().is("FIXTURE_ORIGINAL_FAILURE"));
    events.lock().unwrap().push("cleanup");
    assert_eq!(*events.lock().unwrap(),["current","revoke","cleanup"]);
    assert!(owner.checked::<()>(||panic!("failed operation revived")).is_err());
}
#[test]
fn lifetime_only_shortens_and_exact_expiry_refuses_before_session_or_original_access() {
    let (mut owner,events)=session_fixture();let original=owner.end;
    owner.shorten(original+PROBE).unwrap();assert_eq!(owner.end,original);
    let earlier=Instant::now()+Duration::from_secs(1);owner.shorten(earlier).unwrap();assert_eq!(owner.end,earlier);
    events.lock().unwrap().clear();
    assert!(owner.shorten(Instant::now()).is_err());
    assert_eq!(*events.lock().unwrap(),["revoke"]);
    assert!(owner.checked::<()>(||panic!("expired original accessed")).is_err());
    assert!(!owner.session.live.load(Ordering::SeqCst));
}

#[test]
fn caught_sample_unwind_revokes_same_session_before_caller_cleanup_and_never_revives() {
    let (owner,events)=session_fixture();
    let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
        owner.checked::<()>(||panic!("software original-owner unwind"))));
    assert!(result.is_err());assert!(owner.stop.load(Ordering::SeqCst));
    events.lock().unwrap().push("caller-cleanup");
    assert_eq!(*events.lock().unwrap(),["current","revoke","caller-cleanup"]);
    owner.stop.store(false,Ordering::SeqCst);
    assert!(owner.checked::<()>(||panic!("caught unwind revived original")).is_err());
}

#[test]
fn postcheck_loss_revokes_before_dropping_newly_returned_original_owner() {
    struct Returned(Arc<Mutex<Vec<&'static str>>>);
    impl Drop for Returned {fn drop(&mut self){self.0.lock().unwrap().push("drop-returned-original");}}
    let (owner,events)=session_fixture();
    let result=owner.checked(||{
        owner.session.live.store(false,Ordering::SeqCst);Ok(Returned(events.clone()))
    });
    assert!(result.is_err());
    let events=events.lock().unwrap();
    assert!(events.iter().position(|event|*event=="revoke").unwrap()
        <events.iter().position(|event|*event=="drop-returned-original").unwrap());
}

// The SAME production preparation slot algorithm, using harmless heap owners.
// These fixtures cannot construct a monitor, session, socket or Mach receiver.
struct PreparedFixture {
    identity:Arc<()>,live:Arc<AtomicBool>,events:Arc<Mutex<Vec<&'static str>>>,
}
impl Drop for PreparedFixture {
    fn drop(&mut self) {
        assert!(!self.live.load(Ordering::SeqCst),"original cleanup began before terminal revocation");
        self.events.lock().unwrap().push("drop-prepared-original");
    }
}
fn prepared_fixture(lifetime:&SessionLifetime<SessionFixture>,events:&Arc<Mutex<Vec<&'static str>>>)->PreparedFixture {
    PreparedFixture {identity:Arc::new(()),live:lifetime.session.live.clone(),events:events.clone()}
}
#[test]
fn preparation_postcheck_failure_retains_returned_original_until_revoked_cleanup() {
    let (lifetime,events)=session_fixture();let mut slot=PreparedSlot::empty();
    let result=slot.construct(&lifetime,|_|{
        let original=prepared_fixture(&lifetime,&events);
        lifetime.session.live.store(false,Ordering::SeqCst);Ok(original)
    });
    assert!(result.unwrap_err().is("FIXTURE_SESSION_REVOKED"));
    assert!(slot.owner.is_some());assert!(slot.attempted);
    assert!(!events.lock().unwrap().contains(&"drop-prepared-original"));
    assert!(slot.construct(&lifetime,|_|panic!("late failure replaced original")).is_err());
    drop(slot);
    let events=events.lock().unwrap();
    assert!(events.iter().position(|event|*event=="revoke").unwrap()
        <events.iter().position(|event|*event=="drop-prepared-original").unwrap());
}
#[test]
fn preparation_constructor_error_is_consumed_and_prevents_later_native_attempt() {
    let (lifetime,_events)=session_fixture();let mut slot=PreparedSlot::<()>::empty();
    assert!(slot.construct(&lifetime,|_|Err(err!(EIO,"FIXTURE_CONSTRUCTION_REFUSED"))).unwrap_err().is("FIXTURE_CONSTRUCTION_REFUSED"));
    assert!(slot.attempted && slot.owner.is_none());
    lifetime.stop.store(false,Ordering::SeqCst);
    assert!(slot.construct(&lifetime,|_|panic!("failed constructor was retried")).unwrap_err().is("SUPERVISOR_PREPARATION_ALREADY_ATTEMPTED"));
    assert!(!lifetime.session.live.load(Ordering::SeqCst));
}
#[test]
fn preparation_rebind_never_replaces_or_drops_original_before_terminal_revocation() {
    let (lifetime,events)=session_fixture();let mut slot=PreparedSlot::empty();
    slot.construct(&lifetime,|_|Ok(prepared_fixture(&lifetime,&events))).unwrap();
    let original=slot.get().identity.clone();
    assert!(slot.construct(&lifetime,|_|panic!("original replaced")).is_err());
    assert!(Arc::ptr_eq(&original,&slot.get().identity));
    assert!(!events.lock().unwrap().contains(&"drop-prepared-original"));drop(slot);
}
#[test]
fn preparation_expired_or_stopped_lifetime_runs_no_constructor_and_cannot_retry() {
    for expired in [true,false] {
        let (mut lifetime,_events)=session_fixture();let mut slot=PreparedSlot::<()>::empty();
        if expired {assert!(lifetime.shorten(Instant::now()).is_err());}
        else {lifetime.stop.store(true,Ordering::SeqCst);}
        assert!(slot.construct(&lifetime,|_|panic!("inadmissible constructor ran")).is_err());
        assert!(slot.attempted && slot.owner.is_none());
        lifetime.stop.store(false,Ordering::SeqCst);
        assert!(slot.construct(&lifetime,|_|panic!("expired construction replayed")).is_err());
        assert!(!lifetime.session.live.load(Ordering::SeqCst));
    }
}
#[test]
fn preparation_unwind_revokes_before_dropping_any_previously_retained_original() {
    let (lifetime,events)=session_fixture();let mut first=PreparedSlot::empty();
    first.construct(&lifetime,|_|Ok(prepared_fixture(&lifetime,&events))).unwrap();
    let mut second=PreparedSlot::<()>::empty();
    let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
        second.construct(&lifetime,|_|panic!("software constructor unwind"))));
    assert!(result.is_err());assert!(lifetime.stop.load(Ordering::SeqCst));
    assert!(first.owner.is_some());assert!(!events.lock().unwrap().contains(&"drop-prepared-original"));
    assert!(second.construct(&lifetime,|_|panic!("unwound constructor replayed")).is_err());drop(first);
}
#[test]
fn preparation_every_constructor_and_handoff_preserves_same_earliest_lifetime_and_allocation() {
    let (mut lifetime,events)=session_fixture();let end=Instant::now()+Duration::from_secs(1);
    lifetime.shorten(end).unwrap();let mut first=PreparedSlot::empty();let mut second=PreparedSlot::empty();
    first.construct(&lifetime,|observed|{assert_eq!(observed,end);Ok(prepared_fixture(&lifetime,&events))}).unwrap();
    lifetime.shorten(end+PROBE).unwrap();
    second.construct(&lifetime,|observed|{assert_eq!(observed,end);Ok(prepared_fixture(&lifetime,&events))}).unwrap();
    let identity=first.get().identity.clone();let handed=first.take();
    assert!(Arc::ptr_eq(&identity,&handed.identity));assert!(first.owner.is_none() && first.attempted);
    assert_eq!(lifetime.end,end);lifetime.stop();drop(handed);drop(second);
}

// Synthetic original resources exercise the SAME negative binding/cleanup
// algorithm; they cannot construct native PF owners or ready observations.
struct NotificationFixture {
    identity:Arc<()>,live:Arc<AtomicBool>,stop:Arc<AtomicBool>,events:Arc<Mutex<Vec<&'static str>>>,
    progress_behavior:std::sync::atomic::AtomicUsize,progress_ends:Mutex<Vec<Instant>>,
    collection_generation:Arc<std::sync::atomic::AtomicU64>,
}
impl NotificationDependency<SessionFixture> for NotificationFixture {
    type Collection<'a>=NotificationCollectionFixture<'a>;
    fn begin_collection(&self,end:Instant)->EnclaveResult<Self::Collection<'_>> {
        self.observe_progress(end)?;
        Ok(NotificationCollectionFixture {owner:self,generation:self.collection_generation.load(Ordering::SeqCst),end,armed:true})
    }
    fn require_original(&self,session:&SessionFixture,stop:&Arc<AtomicBool>,end:Instant)->EnclaveResult<()> {
        self.events.lock().unwrap().push("notification-binding");
        if !Arc::ptr_eq(&self.live,&session.live) || !Arc::ptr_eq(&self.stop,stop) || Instant::now()>=end {
            self.live.store(false,Ordering::SeqCst);session.live.store(false,Ordering::SeqCst);
            self.stop.store(true,Ordering::SeqCst);stop.store(true,Ordering::SeqCst);
            fail!(EACCES,"FIXTURE_NOTIFICATION_BINDING");
        }
        Ok(())
    }
    fn observe_progress(&self,end:Instant)->EnclaveResult<()> {
        self.events.lock().unwrap().push("notification-progress");
        self.progress_ends.lock().unwrap().push(end);
        match self.progress_behavior.load(Ordering::SeqCst) {
            0=>Ok(()),
            1=>Err(err!(EIO,"FIXTURE_NOTIFICATION_PROGRESS_REFUSED")),
            2=>panic!("fixture notification progress unwind"),
            3=>{self.live.store(false,Ordering::SeqCst);Ok(())},
            4=>{std::thread::sleep(end.saturating_duration_since(Instant::now())+Duration::from_millis(1));Ok(())},
            _=>unreachable!(),
        }
    }
    fn request_stop(&self) {
        self.live.store(false,Ordering::SeqCst);self.stop.store(true,Ordering::SeqCst);
        self.events.lock().unwrap().push("notification-stop");
    }
}
impl Drop for NotificationFixture {
    fn drop(&mut self) {
        assert!(!self.live.load(Ordering::SeqCst) && self.stop.load(Ordering::SeqCst),
            "notification native cleanup must follow original atomic veto");
        self.events.lock().unwrap().push("notification-drop");
    }
}
fn notification_fixture(lifetime:&SessionLifetime<SessionFixture>)->NotificationFixture {
    NotificationFixture {identity:Arc::new(()),live:lifetime.session.live.clone(),
        stop:lifetime.stop.clone(),events:lifetime.session.events.clone(),
        progress_behavior:std::sync::atomic::AtomicUsize::new(0),progress_ends:Mutex::new(Vec::new()),
        collection_generation:Arc::new(std::sync::atomic::AtomicU64::new(0))}
}

#[test]
fn notification_progress_checks_same_original_before_and_after_and_only_shortens_cap() {
    let (lifetime,events)=session_fixture();let notification=notification_fixture(&lifetime);
    let original=notification.identity.clone();let shorter=Instant::now()+Duration::from_secs(1);
    require_notification(&lifetime,&notification,shorter).unwrap();
    require_notification(&lifetime,&notification,lifetime.end+PROBE).unwrap();
    assert_eq!(*notification.progress_ends.lock().unwrap(),[shorter,lifetime.end]);
    assert!(Arc::ptr_eq(&original,&notification.identity));
    assert!(lifetime.session.live.load(Ordering::SeqCst) && !lifetime.stop.load(Ordering::SeqCst));
    let observed=events.lock().unwrap();
    let bindings=observed.iter().enumerate().filter_map(|(i,e)|(*e=="notification-binding").then_some(i)).collect::<Vec<_>>();
    let progress=observed.iter().enumerate().filter_map(|(i,e)|(*e=="notification-progress").then_some(i)).collect::<Vec<_>>();
    assert_eq!(bindings.len(),4);assert_eq!(progress.len(),2);
    assert!(bindings[0]<progress[0] && progress[0]<bindings[1] && bindings[2]<progress[1] && progress[1]<bindings[3]);
    drop(observed);stop_notification(&lifetime,&notification);drop(notification);
}

#[test]
fn notification_progress_failure_or_unwind_revokes_both_originals_before_cleanup_and_cannot_retry() {
    for behavior in [1,2] {
        let (lifetime,events)=session_fixture();let notification=notification_fixture(&lifetime);
        notification.progress_behavior.store(behavior,Ordering::SeqCst);
        let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
            require_notification(&lifetime,&notification,lifetime.end)));
        if behavior==1 {assert!(result.unwrap().unwrap_err().is("FIXTURE_NOTIFICATION_PROGRESS_REFUSED"));}
        else {assert!(result.is_err());}
        assert!(!lifetime.session.live.load(Ordering::SeqCst) && lifetime.stop.load(Ordering::SeqCst));
        notification.progress_behavior.store(0,Ordering::SeqCst);lifetime.stop.store(false,Ordering::SeqCst);
        assert!(require_notification(&lifetime,&notification,lifetime.end).is_err());
        assert_eq!(notification.progress_ends.lock().unwrap().len(),1,"terminal observer must not run again");
        events.lock().unwrap().push("other-native-drop");drop(notification);
        let observed=events.lock().unwrap();
        let revoked=observed.iter().position(|e|*e=="revoke").unwrap();
        let stopped=observed.iter().position(|e|*e=="notification-stop").unwrap();
        assert!(revoked<stopped && stopped<observed.iter().position(|e|*e=="other-native-drop").unwrap());
        assert!(stopped<observed.iter().position(|e|*e=="notification-drop").unwrap());
    }
}

#[test]
fn notification_progress_success_cannot_hide_original_session_loss_or_late_completion() {
    for behavior in [3,4] {
        let (lifetime,events)=session_fixture();let notification=notification_fixture(&lifetime);
        notification.progress_behavior.store(behavior,Ordering::SeqCst);
        let end=if behavior==4 {Instant::now()+Duration::from_millis(10)}else{lifetime.end};
        assert!(require_notification(&lifetime,&notification,end).is_err());
        assert_eq!(*notification.progress_ends.lock().unwrap(),[end]);
        assert!(!lifetime.session.live.load(Ordering::SeqCst) && lifetime.stop.load(Ordering::SeqCst));
        events.lock().unwrap().push("other-native-drop");drop(notification);
        let observed=events.lock().unwrap();
        assert!(observed.iter().position(|e|*e=="notification-stop").unwrap()
            <observed.iter().position(|e|*e=="other-native-drop").unwrap());
    }
}

#[test]
fn notification_expired_shorter_cap_reaches_no_worker_and_remains_terminal() {
    let (lifetime,events)=session_fixture();let notification=notification_fixture(&lifetime);
    assert!(require_notification(&lifetime,&notification,Instant::now()).is_err());
    assert!(notification.progress_ends.lock().unwrap().is_empty());
    assert!(!lifetime.session.live.load(Ordering::SeqCst) && lifetime.stop.load(Ordering::SeqCst));
    lifetime.stop.store(false,Ordering::SeqCst);
    assert!(require_notification(&lifetime,&notification,lifetime.end+PROBE).is_err());
    assert!(notification.progress_ends.lock().unwrap().is_empty());
    assert!(!events.lock().unwrap().contains(&"notification-progress"));drop(notification);
}

#[test]
fn pf_owner_retained_before_postcheck_failure_and_cancelled_before_other_drops() {
    let (lifetime,events)=session_fixture();let mut slot=PreparedSlot::empty();let mut identity=None;
    assert!(slot.construct(&lifetime,|_|{
        let original=notification_fixture(&lifetime);identity=Some(original.identity.clone());
        lifetime.session.live.store(false,Ordering::SeqCst);Ok(original)
    }).is_err());
    assert!(Arc::ptr_eq(&slot.owner.as_ref().unwrap().identity,&identity.unwrap()));
    assert!(!events.lock().unwrap().contains(&"notification-drop"));
    stop_notification(&lifetime,slot.owner.as_ref().unwrap());
    events.lock().unwrap().push("other-native-drop");drop(slot);
    let events=events.lock().unwrap();
    let stop=events.iter().position(|e|*e=="notification-stop").unwrap();
    assert!(stop<events.iter().position(|e|*e=="other-native-drop").unwrap());
    assert!(stop<events.iter().position(|e|*e=="notification-drop").unwrap());
}

#[test]
fn pf_owner_wrong_session_or_stop_never_constructs_readiness_owner() {
    for wrong_session in [false,true] {
        let (original,_)=session_fixture();let notification=notification_fixture(&original);
        let (mut offered,events)=session_fixture();
        if !wrong_session {offered.session.live=original.session.live.clone();}
        // With matching session the independently allocated stop is wrong;
        // with wrong session use the exact original stop to isolate that case.
        if wrong_session {offered.stop=original.stop.clone();}
        assert!(require_notification(&offered,&notification,offered.end).is_err());
        assert!(!original.session.live.load(Ordering::SeqCst));
        assert!(!offered.session.live.load(Ordering::SeqCst));
        assert!(original.stop.load(Ordering::SeqCst) && offered.stop.load(Ordering::SeqCst));
        assert!(!events.lock().unwrap().contains(&"current"),"binding refusal precedes later native/session work");
        assert!(notification.progress_ends.lock().unwrap().is_empty(),"wrong original must never reach worker observation");
        drop(notification);
    }
}

#[test]
fn pf_owner_handoff_is_same_allocation_and_does_not_observe_pf_terms() {
    let (lifetime,events)=session_fixture();let mut slot=PreparedSlot::empty();
    slot.construct(&lifetime,|_|Ok(notification_fixture(&lifetime))).unwrap();
    let identity=slot.owner.as_ref().unwrap().identity.clone();
    require_notification(&lifetime,slot.owner.as_ref().unwrap(),lifetime.end).unwrap();
    let handed=slot.take();assert!(Arc::ptr_eq(&handed.identity,&identity));
    require_notification(&lifetime,&handed,lifetime.end).unwrap();
    assert!(!lifetime.stop.load(Ordering::SeqCst));
    assert_eq!(events.lock().unwrap().iter().filter(|e|**e=="notification-binding").count(),4);
    assert_eq!(events.lock().unwrap().iter().filter(|e|**e=="notification-progress").count(),2);
    // The actual constructor guard must veto both originals before argument
    // teardown even if a later constructor check unwinds after handoff.
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(||{
        let _guard=NotificationCleanup {session:&lifetime.session,stop:&lifetime.stop,
            notification:&handed,armed:true};
        panic!("fixture later readiness construction unwind");
    })).is_err());
    assert!(lifetime.stop.load(Ordering::SeqCst));
    assert!(Arc::ptr_eq(&handed.identity,&identity));
    events.lock().unwrap().push("other-native-drop");drop(handed);
    let events=events.lock().unwrap();
    assert!(events.iter().position(|e|*e=="notification-stop").unwrap()
        <events.iter().position(|e|*e=="other-native-drop").unwrap());
}

// Real SOFTWARE sockets and actual JoinHandles exercise the production
// ownership/retirement algorithms. No native peer, owner, PF or readiness is
// fabricated. Five-second fixture waits do not define a lifecycle budget.
mod ipc_worker_retention {
    use super::*;
    use std::{cell::OnceCell, io::{Read,Write}, os::unix::fs::DirBuilderExt,
        rc::Rc, sync::OnceLock, thread::JoinHandle};

    fn shutdown()->Arc<IpcShutdown> {
        IpcShutdown::new(IpcSession::Fixture {revoked:Arc::new(AtomicBool::new(false)),process_unknown:Arc::new(AtomicBool::new(false))},Arc::new(AtomicBool::new(false)))
    }
    fn revoked(shutdown:&IpcShutdown)->bool {
        match &shutdown.session {
            IpcSession::Fixture {revoked,..}=>revoked.load(Ordering::SeqCst),
            IpcSession::Native(_)=>panic!("software fixture obtained native authority"),
        }
    }
    fn wait_finished<T>(worker:&JoinHandle<T>) {
        let end=Instant::now()+Duration::from_secs(5);
        while !worker.is_finished() && Instant::now()<end {std::thread::yield_now();}
        assert!(worker.is_finished(),"bounded software fixture did not finish");
    }
    struct LocalListener {root:PathBuf,listener:Option<UnixListener>}
    impl LocalListener {
        fn new()->Self {
            let root=PathBuf::from(format!(".ryw-{}-{}",std::process::id(),hex::encode(&crate::rng::bytes32()[..6])));
            std::fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            let listener=UnixListener::bind(root.join("s")).unwrap();Self {root,listener:Some(listener)}
        }
        fn take(&mut self)->UnixListener {self.listener.take().unwrap()}
    }
    impl Drop for LocalListener {
        fn drop(&mut self) {let _=std::fs::remove_file(self.root.join("s"));let _=std::fs::remove_dir(&self.root);}
    }
    struct StreamOwner {stream:UnixStream,shutdown:Arc<IpcShutdown>,dropped:Arc<AtomicBool>}
    impl Drop for StreamOwner {
        fn drop(&mut self) {
            assert!(revoked(&self.shutdown) && self.shutdown.stop.load(Ordering::SeqCst),
                "original session veto must precede stream cleanup");
            self.dropped.store(true,Ordering::SeqCst);
        }
    }
    struct BlockedIo {client:UnixStream,release:mpsc::SyncSender<()>,dropped:Arc<AtomicBool>}
    impl BlockedIo {
        fn pending(&mut self) {
            assert!(!self.dropped.load(Ordering::SeqCst));let mut byte=[0;1];
            assert_eq!(self.client.read(&mut byte).unwrap_err().kind(),std::io::ErrorKind::WouldBlock);
        }
        fn release(&self) {self.release.try_send(()).unwrap();}
        fn closed(&mut self) {
            let end=Instant::now()+Duration::from_secs(5);
            while !self.dropped.load(Ordering::SeqCst) && Instant::now()<end {std::thread::yield_now();}
            assert!(self.dropped.load(Ordering::SeqCst));
            // `dropped` is set before the OS stream field closes, so allow only
            // the fixture endpoint for that actual final close to complete.
            let mut byte=[0;1];
            loop {match self.client.read(&mut byte) {
                Ok(0)=>break,Err(error) if error.kind()==std::io::ErrorKind::WouldBlock && Instant::now()<end=>std::thread::yield_now(),
                other=>panic!("expected actual software stream close, got {other:?}"),
            }}
        }
    }
    impl Drop for BlockedIo {fn drop(&mut self){let _=self.release.try_send(());}}
    fn blocked<T:Send+'static>(shutdown:Arc<IpcShutdown>,result:T)->(JoinHandle<T>,BlockedIo) {
        let (mut client,server)=UnixStream::pair().unwrap();client.set_nonblocking(true).unwrap();
        let dropped=Arc::new(AtomicBool::new(false));
        let mut stream=StreamOwner {stream:server,shutdown,dropped:dropped.clone()};
        let (arrived,wait)=mpsc::sync_channel(1);let (release,receive)=mpsc::sync_channel(1);
        let worker=std::thread::spawn(move|| {
            let mut byte=[0;1];stream.stream.read_exact(&mut byte).unwrap();assert_eq!(byte,[0x63]);
            arrived.send(()).unwrap();receive.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(stream);result
        });
        client.write_all(&[0x63]).unwrap();wait.recv_timeout(Duration::from_secs(5)).unwrap();
        (worker,BlockedIo {client,release,dropped})
    }

    #[test]
    fn completed_real_peer_exchange_joins_without_unknown_or_retained_owner() {
        let shutdown=shutdown();let slot=OnceLock::new();let mut fixture=LocalListener::new();
        let listener=fixture.take();let mut client=UnixStream::connect(fixture.root.join("s")).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let (mut stream,_)=listener.accept().unwrap();
        let mut workers=PeerWorkers::new(listener,shutdown.clone(),&slot);
        workers.get().workers.push(std::thread::spawn(move|| {
            let mut bytes=[0;3];stream.read_exact(&mut bytes).unwrap();assert_eq!(&bytes,b"req");
            stream.write_all(b"ack").unwrap();
        }));
        client.write_all(b"req").unwrap();let mut response=[0;3];client.read_exact(&mut response).unwrap();assert_eq!(&response,b"ack");
        wait_finished(&workers.get().workers[0]);workers.get().join_finished().unwrap();
        assert!(workers.get().workers.is_empty());assert!(!shutdown.stop.load(Ordering::SeqCst));
        drop(workers);assert!(slot.get().is_none());assert!(!shutdown.cleanup_unknown.load(Ordering::SeqCst));
        assert_eq!(shutdown.retained_peer_workers.load(Ordering::SeqCst),0);assert!(revoked(&shutdown));
    }

    #[test]
    fn pending_real_peer_keeps_exact_handle_listener_quota_and_stream_after_retirement() {
        let shutdown=shutdown();let slot=OnceLock::new();let mut fixture=LocalListener::new();
        let listener=fixture.take();let original_fd=listener.as_raw_fd();
        let mut workers=PeerWorkers::new(listener,shutdown.clone(),&slot);
        let counts=workers.get().counts.clone();counts.lock().unwrap().insert(703,1);
        let (worker,mut io)=blocked(shutdown.clone(),());let identity=worker.thread().id();workers.get().workers.push(worker);
        // Retirement must not acquire the evidence/quota mutex, even expired.
        let locked=counts.lock().unwrap();drop(workers);
        assert!(revoked(&shutdown) && shutdown.stop.load(Ordering::SeqCst));
        let retained=slot.get().unwrap();assert_eq!(retained.listener.as_raw_fd(),original_fd);
        assert!(Arc::ptr_eq(&retained.counts,&counts));assert_eq!(retained.workers.len(),1);
        assert_eq!(retained.workers[0].thread().id(),identity);assert_eq!(shutdown.retained_peer_workers.load(Ordering::SeqCst),1);
        assert!(shutdown.cleanup_unknown.load(Ordering::SeqCst));io.pending();drop(locked);
        io.release();wait_finished(&retained.workers[0]);io.closed();
        assert!(shutdown.cleanup_unknown.load(Ordering::SeqCst),"late closure cannot clear UNKNOWN");
        let mut retained=slot.into_inner().unwrap();retained.join_finished().unwrap();assert!(retained.workers.is_empty());
        assert_eq!(shutdown.retained_peer_workers.load(Ordering::SeqCst),1,"charge records retirement, never a cleanup claim");
    }

    #[test]
    fn retiring_multiple_peers_keeps_every_unfinished_handle_past_first_pending_worker() {
        let shutdown=shutdown();let slot=OnceLock::new();let mut fixture=LocalListener::new();
        let mut workers=PeerWorkers::new(fixture.take(),shutdown.clone(),&slot);
        let (one,mut first)=blocked(shutdown.clone(),());let first_id=one.thread().id();
        let (two,mut second)=blocked(shutdown.clone(),());let second_id=two.thread().id();
        workers.get().workers.push(one);workers.get().workers.push(std::thread::spawn(||()));workers.get().workers.push(two);
        wait_finished(&workers.get().workers[1]);drop(workers);
        let retained=slot.get().unwrap();assert_eq!(retained.workers.len(),2);
        let ids=retained.workers.iter().map(|worker|worker.thread().id()).collect::<Vec<_>>();
        assert!(ids.contains(&first_id) && ids.contains(&second_id));assert_eq!(shutdown.retained_peer_workers.load(Ordering::SeqCst),2);
        first.pending();second.pending();first.release();second.release();
        for worker in &retained.workers {wait_finished(worker);}first.closed();second.closed();
        let mut retained=slot.into_inner().unwrap();retained.join_finished().unwrap();
    }

    #[test]
    fn peer_retirement_collision_preserves_both_originals_and_sticky_unknown_charge() {
        let shutdown=shutdown();let slot=OnceLock::new();let mut sockets=Vec::new();let mut fixture=LocalListener::new();
        let mut first=PeerWorkers::new(fixture.take(),shutdown.clone(),&slot);
        let (one,first_io)=blocked(shutdown.clone(),());let identity=one.thread().id();first.get().workers.push(one);sockets.push(first_io);drop(first);
        let mut fixture2=LocalListener::new();let mut second=PeerWorkers::new(fixture2.take(),shutdown.clone(),&slot);
        let (two,second_io)=blocked(shutdown.clone(),());second.get().workers.push(two);sockets.push(second_io);drop(second);
        assert_eq!(slot.get().unwrap().workers[0].thread().id(),identity);
        assert_eq!(shutdown.retention_collisions.load(Ordering::SeqCst),1);assert_eq!(shutdown.retained_peer_workers.load(Ordering::SeqCst),2);
        for io in &mut sockets {io.pending();io.release();io.closed();}
        wait_finished(&slot.get().unwrap().workers[0]);let mut retained=slot.into_inner().unwrap();retained.join_finished().unwrap();
        assert!(shutdown.cleanup_unknown.load(Ordering::SeqCst));
    }

    struct RootOriginals {
        original:UnixStream,receive:mpsc::Receiver<()>,affinity:Rc<()>,
        shutdown:Arc<IpcShutdown>,dropped:Arc<AtomicBool>,
        blocking_stop:Option<crate::power::selected_owner_listener::ReadinessStopFixture>,
    }
    impl Drop for RootOriginals {
        fn drop(&mut self) {
            assert!(revoked(&self.shutdown) && self.shutdown.stop.load(Ordering::SeqCst));
            if let Some(stop)=&self.blocking_stop {stop.stop();}
            self.dropped.store(true,Ordering::SeqCst);
        }
    }
    fn originals(shutdown:Arc<IpcShutdown>)->(RootOriginals,UnixStream,mpsc::SyncSender<()>,Arc<AtomicBool>) {
        let (original,observer)=UnixStream::pair().unwrap();observer.set_nonblocking(true).unwrap();
        let (send,receive)=mpsc::sync_channel(1);let dropped=Arc::new(AtomicBool::new(false));
        (RootOriginals {original,receive,affinity:Rc::new(()),shutdown,dropped:dropped.clone(),
            blocking_stop:None},observer,send,dropped)
    }

    #[test]
    fn completed_real_server_releases_original_bundle_without_unknown_retention() {
        let shutdown=shutdown();let slot=OnceCell::new();let (roots,mut observer,_send,dropped)=originals(shutdown.clone());
        let mut serving=ServingOwner::new(roots,shutdown.clone(),&slot);
        serving.get().server=Some(std::thread::spawn(||Ok(())));
        serving.get().finish_server(Instant::now()+Duration::from_secs(5)).unwrap();
        assert!(serving.get().server.is_none());assert!(!dropped.load(Ordering::SeqCst));drop(serving);
        assert!(dropped.load(Ordering::SeqCst));assert!(slot.get().is_none());let mut byte=[0;1];assert_eq!(observer.read(&mut byte).unwrap(),0);
        assert!(!shutdown.cleanup_unknown.load(Ordering::SeqCst));assert!(!shutdown.root_retained.load(Ordering::SeqCst));
    }

    #[test]
    fn expired_server_cleanup_retains_same_thread_affine_root_receiver_handle_and_socket() {
        let shutdown=shutdown();let slot=OnceCell::new();let (roots,mut observer,send,dropped)=originals(shutdown.clone());
        let original_fd=roots.original.as_raw_fd();let affinity=roots.affinity.clone();
        let mut serving=ServingOwner::new(roots,shutdown.clone(),&slot);
        let (worker,mut io)=blocked(shutdown.clone(),Ok(()));let identity=worker.thread().id();serving.get().server=Some(worker);
        assert!(serving.get().finish_server(Instant::now()).unwrap_err().is("SUPERVISOR_DEPENDENCY_SERVER_CLEANUP_UNKNOWN"));
        drop(serving);let retained=*slot.get().unwrap();drop(slot); // TLS-cell destruction must not destroy retained owners.
        assert_eq!(retained.originals.original.as_raw_fd(),original_fd);assert!(Rc::ptr_eq(&retained.originals.affinity,&affinity));
        assert_eq!(retained.server.as_ref().unwrap().thread().id(),identity);assert!(!dropped.load(Ordering::SeqCst));
        send.try_send(()).unwrap();assert_eq!(retained.originals.receive.try_recv().unwrap(),());
        let mut byte=[0;1];assert_eq!(observer.read(&mut byte).unwrap_err().kind(),std::io::ErrorKind::WouldBlock);
        assert!(shutdown.root_retained.load(Ordering::SeqCst));io.pending();io.release();wait_finished(retained.server.as_ref().unwrap());io.closed();
        assert!(shutdown.cleanup_unknown.load(Ordering::SeqCst) && !dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn caught_coordinator_unwind_vetoes_before_retaining_unfinished_originals() {
        let shutdown=shutdown();let slot=OnceCell::new();let (roots,_observer,_send,dropped)=originals(shutdown.clone());
        let (worker,mut io)=blocked(shutdown.clone(),Ok(()));let identity=worker.thread().id();
        let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut serving=ServingOwner::new(roots,shutdown.clone(),&slot);serving.get().server=Some(worker);
            panic!("software coordinator unwind after actual worker creation");
        }));
        assert!(result.is_err());let retained=*slot.get().unwrap();assert_eq!(retained.server.as_ref().unwrap().thread().id(),identity);
        assert!(revoked(&shutdown) && shutdown.root_retained.load(Ordering::SeqCst));assert!(!dropped.load(Ordering::SeqCst));
        io.pending();io.release();wait_finished(retained.server.as_ref().unwrap());io.closed();
    }

    #[test]
    fn completed_server_still_retains_root_when_original_peer_cleanup_is_unknown() {
        let shutdown=shutdown();let peer_slot=OnceLock::new();let root_slot=OnceCell::new();let mut fixture=LocalListener::new();
        let mut peers=PeerWorkers::new(fixture.take(),shutdown.clone(),&peer_slot);
        let (peer,mut io)=blocked(shutdown.clone(),());let peer_id=peer.thread().id();peers.get().workers.push(peer);
        // Models the actual server's returned peer-cleanup error AFTER its
        // same PeerWorkers Drop has preserved the accepted stream/handle.
        drop(peers);let (roots,_observer,send,dropped)=originals(shutdown.clone());
        let mut serving=ServingOwner::new(roots,shutdown.clone(),&root_slot);
        serving.get().server=Some(std::thread::spawn(||Err(err!(EIO,"SUPERVISOR_DEPENDENCY_PEER_CLEANUP_UNKNOWN"))));
        assert!(serving.get().finish_server(Instant::now()+Duration::from_secs(5)).unwrap_err().is("SUPERVISOR_DEPENDENCY_PEER_CLEANUP_UNKNOWN"));
        assert!(serving.get().server.is_none());drop(serving);assert!(root_slot.get().is_some());assert!(!dropped.load(Ordering::SeqCst));
        send.try_send(()).unwrap();let retained=peer_slot.get().unwrap();assert_eq!(retained.workers[0].thread().id(),peer_id);
        io.release();wait_finished(&retained.workers[0]);io.closed();let mut retained=peer_slot.into_inner().unwrap();retained.join_finished().unwrap();
        assert!(shutdown.server_error.load(Ordering::SeqCst) && shutdown.cleanup_unknown.load(Ordering::SeqCst));
    }

    #[test]
    fn joined_peer_panic_is_terminal_unknown_and_never_a_successful_cleanup() {
        let shutdown=shutdown();let slot=OnceLock::new();let mut fixture=LocalListener::new();
        let mut peers=PeerWorkers::new(fixture.take(),shutdown.clone(),&slot);
        peers.get().workers.push(std::thread::spawn(||panic!("software peer worker panic")));
        wait_finished(&peers.get().workers[0]);assert!(peers.get().join_finished().unwrap_err().is("SUPERVISOR_DEPENDENCY_PEER_UNWOUND"));
        assert!(revoked(&shutdown) && shutdown.joined_unwind.load(Ordering::SeqCst));drop(peers);
        assert!(slot.get().is_some());assert!(shutdown.cleanup_unknown.load(Ordering::SeqCst));
    }

    #[test]
    fn process_unknown_refuses_every_new_owner_attempt_before_constructor_or_spawn() {
        let original=shutdown();let admitted=original.process_unknown();
        require_ipc_admission(admitted).unwrap();original.unknown();
        let mut constructed=0;
        for _ in 0..4 {
            let attempt:EnclaveResult<()>=(|| {
                // SAME atomic admission algorithm called before native prepare
                // session capture, serve bind and accepted-worker construction.
                require_ipc_admission(admitted)?;
                constructed+=1;
                let mut fixture=LocalListener::new();let slot=OnceLock::new();
                let _workers=PeerWorkers::new(fixture.take(),original.clone(),&slot);
                Ok(())
            })();
            assert!(attempt.unwrap_err().is("SUPERVISOR_DEPENDENCY_PRIOR_CLEANUP_UNKNOWN"));
        }
        assert_eq!(constructed,0);assert!(revoked(&original));
        // A later domain with the same original process flag cannot bypass it.
        let process_unknown=match &original.session {
            IpcSession::Fixture {process_unknown,..}=>process_unknown.clone(),_=>unreachable!(),
        };
        let offered=IpcShutdown::new(IpcSession::Fixture {revoked:Arc::new(AtomicBool::new(false)),process_unknown},
            Arc::new(AtomicBool::new(false)));
        assert!(offered.require_admission().is_err());assert!(revoked(&offered));
    }


    #[test]
    fn unstarted_peer_payload_veto_precedes_blocked_original_quota_drop() {
        let shutdown=shutdown();let (stream,_client)=UnixStream::pair().unwrap();
        let counts=Arc::new(Mutex::new(BTreeMap::from([(703,1)])));let locked=counts.lock().unwrap();
        let (send,_receive)=mpsc::sync_channel(1);
        let input=PeerInput {stream:Some(stream),_charge:ConnectionCharge {uid:703,counts:counts.clone()},
            policy:Some(PeerPolicy::allow([])),send:Some(send),shutdown:shutdown.clone(),started:false};
        // Failed std::thread::spawn drops this SAME unstarted closed payload.
        // Drop runs on a thread here only so the test can hold the quota mutex.
        let worker=std::thread::spawn(move||drop(input));let end=Instant::now()+Duration::from_secs(5);
        while !revoked(&shutdown) && Instant::now()<end {std::thread::yield_now();}
        assert!(revoked(&shutdown) && shutdown.stop.load(Ordering::SeqCst));assert!(!worker.is_finished());
        drop(locked);wait_finished(&worker);worker.join().unwrap();assert_eq!(counts.lock().unwrap().get(&703),Some(&0));
    }


    #[test]
    fn unknown_retirement_precedes_actual_root_life_and_listener_cell_stop_locks() {
        use crate::power::selected_owner_listener::ReadinessStopFixture;
        for cell in [false,true] {for explicit_finish in [false,true] {
            let shutdown=shutdown();let slot=OnceCell::new();let mut fixture=LocalListener::new();
            let blocking=ReadinessStopFixture::new(fixture.take());
            let (ready,wait_ready)=mpsc::sync_channel(1);let (release,wait_release)=mpsc::sync_channel(1);
            let hold=blocking.clone();let holder=std::thread::spawn(move||hold.hold(cell,ready,wait_release));
            wait_ready.recv_timeout(Duration::from_secs(5)).unwrap();
            // Demonstrate that this exact production Control::stop really
            // waits at the held Life/ListenerCell boundary, rather than using
            // an atomic-only cleanup fixture that omits the blocking chain.
            let stop=blocking.clone();let probe=std::thread::spawn(move||stop.stop());
            let end=Instant::now()+Duration::from_secs(5);
            while blocking.stop_entries()==0 && Instant::now()<end {std::thread::yield_now();}
            assert_eq!(blocking.stop_entries(),1);assert!(!probe.is_finished());
            let (mut roots,_observer,send,dropped)=originals(shutdown.clone());roots.blocking_stop=Some(blocking.clone());
            let original_fd=roots.original.as_raw_fd();let affinity=roots.affinity.clone();
            let mut serving=ServingOwner::new(roots,shutdown.clone(),&slot);
            let (worker,mut io)=blocked(shutdown.clone(),Ok(()));let identity=worker.thread().id();serving.get().server=Some(worker);
            if explicit_finish {
                assert!(serving.get().finish_server(Instant::now()).unwrap_err().is("SUPERVISOR_DEPENDENCY_SERVER_CLEANUP_UNKNOWN"));
            }
            drop(serving);
            // All of these observations occur BEFORE releasing the actual
            // production stop lock. An accidental ordinary root Drop would
            // enter blocking.stop(), wait behind the probe, and fail this case.
            let retained=*slot.get().unwrap();assert_eq!(retained.originals.original.as_raw_fd(),original_fd);
            assert!(Rc::ptr_eq(&retained.originals.affinity,&affinity));assert_eq!(retained.server.as_ref().unwrap().thread().id(),identity);
            assert!(shutdown.cleanup_unknown.load(Ordering::SeqCst) && shutdown.root_retained.load(Ordering::SeqCst));
            assert!(revoked(&shutdown));assert!(!dropped.load(Ordering::SeqCst));assert_eq!(blocking.stop_entries(),1);
            send.try_send(()).unwrap();assert!(!probe.is_finished());io.pending();
            release.send(()).unwrap();assert!(holder.join().unwrap(),"retirement waited for the actual root cleanup lock");
            probe.join().unwrap();io.release();wait_finished(retained.server.as_ref().unwrap());io.closed();
            assert!(!dropped.load(Ordering::SeqCst),"late completion released UNKNOWN original bundle");
        }}
    }

}


#[test]
fn readiness_concrete_guard_endpoint_and_terminal_veto_cannot_be_reset_by_fixture_liveness() {
    for later in [false,true] {
        let end=Instant::now()+PROBE;let valid=AtomicBool::new(true);
        let calls=std::sync::atomic::AtomicUsize::new(0);let failed=AtomicBool::new(false);
        let mut guard=SelectedReadinessIoGuard::fixture(end,&valid,&calls,&failed);
        let changed=if later {end+Duration::from_secs(1)}else{end-Duration::from_secs(1)};
        assert!(guard.current(changed,None).is_err());assert!(failed.load(Ordering::SeqCst));
        assert_eq!(calls.load(Ordering::SeqCst),0);
        valid.store(true,Ordering::SeqCst);
        assert!(guard.current(end,None).is_err());assert_eq!(calls.load(Ordering::SeqCst),0);
    }
}

#[test]
fn readiness_concrete_guard_native_work_lateness_or_unwind_is_terminal_before_caller_recovers() {
    for unwind in [false,true] {
        let end=Instant::now()+if unwind {PROBE}else{Duration::from_millis(20)};
        let valid=AtomicBool::new(true);let calls=std::sync::atomic::AtomicUsize::new(0);let failed=AtomicBool::new(false);
        let mut guard=SelectedReadinessIoGuard::fixture(end,&valid,&calls,&failed);
        if let ReadinessOriginal::Fixture {delay,panic,..}=&mut guard.original {
            *delay=if unwind {Duration::ZERO}else{Duration::from_millis(40)};*panic=unwind;
        }
        let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||guard.current(end,None)));
        assert!(result.is_err() || result.unwrap().is_err());assert!(failed.load(Ordering::SeqCst));
        assert_eq!(calls.load(Ordering::SeqCst),1);
        valid.store(true,Ordering::SeqCst);assert!(guard.current(end,None).is_err());
        assert_eq!(calls.load(Ordering::SeqCst),1);
    }
}

#[test]
fn readiness_outer_veto_survives_raw_transport_success_through_strict_decode_failure_and_unwind() {
    use std::io::Read;
    for unwind in [false,true] {
        let (client,mut server)=UnixStream::pair().unwrap();let mut stream=Some(client);
        let worker=std::thread::spawn(move|| {
            let _request=ipc::read_frame_timed(&mut server,&limits()).unwrap();
            ipc::write_frame_timed(&mut server,&[0xff],&limits()).unwrap();
            server.set_nonblocking(false).unwrap();server.set_read_timeout(Some(PROBE)).unwrap();let mut byte=[0;1];assert_eq!(server.read(&mut byte).unwrap(),0);
        });
        let end=Instant::now()+PROBE;let valid=AtomicBool::new(true);
        let calls=std::sync::atomic::AtomicUsize::new(0);let failed=AtomicBool::new(false);
        let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||->EnclaveResult<()> {
            let guard=SelectedReadinessIoGuard::fixture(end,&valid,&calls,&failed);
            let mut operation=ReadinessOperation {guard,stream:&mut stream,armed:true};
            let bytes=ipc::exchange_selected_readiness_until(operation.stream,&mut operation.guard,&[0],end)?;
            assert!(!failed.load(Ordering::SeqCst),"raw transport alone does not disarm outer owner");
            if unwind {panic!("SCRIPTED_READINESS_STRICT_DECODER_UNWIND");}
            let _=strict_decode::<ipc::Reply<Observation>>(&bytes)?;operation.complete();Ok(())
        }));
        assert!(result.is_err() || result.unwrap().is_err());assert!(failed.load(Ordering::SeqCst));
        assert!(!valid.load(Ordering::SeqCst));assert!(stream.is_none());worker.join().unwrap();
    }
}

#[test]
fn readiness_outer_veto_remains_armed_for_final_context_loss_after_complete_valid_observation() {
    use std::io::Read;
    let (client,mut server)=UnixStream::pair().unwrap();let mut stream=Some(client);
    let worker=std::thread::spawn(move|| {
        let request=strict_decode::<Request>(&ipc::read_frame_timed(&mut server,&limits()).unwrap()).unwrap();
        ipc::write_frame_timed(&mut server,&ipc::to_cbor(&ipc::Reply::Ok(observation(request))).unwrap(),&limits()).unwrap();
        server.set_nonblocking(false).unwrap();server.set_read_timeout(Some(PROBE)).unwrap();let mut byte=[0;1];assert_eq!(server.read(&mut byte).unwrap(),0);
    });
    let end=Instant::now()+PROBE;let valid=AtomicBool::new(true);
    let calls=std::sync::atomic::AtomicUsize::new(0);let failed=AtomicBool::new(false);
    {
        let guard=SelectedReadinessIoGuard::fixture(end,&valid,&calls,&failed);
        let mut operation=ReadinessOperation {guard,stream:&mut stream,armed:true};
        exchange_owned(&mut operation,&binding(),&mut None,end).unwrap();
        assert!(!failed.load(Ordering::SeqCst));valid.store(false,Ordering::SeqCst);
        assert!(operation.current().is_err());
    }
    assert!(failed.load(Ordering::SeqCst));assert!(stream.is_none());worker.join().unwrap();
}

#[test]
fn readiness_initial_probe_success_does_not_disarm_surrounding_assignment_followup_owner() {
    use std::io::Read;
    let (client,mut server)=UnixStream::pair().unwrap();let mut stream=Some(client);
    let worker=std::thread::spawn(move|| {
        for _ in 0..2 {
            let request=strict_decode::<Request>(&ipc::read_frame_timed(&mut server,&limits()).unwrap()).unwrap();
            ipc::write_frame_timed(&mut server,&ipc::to_cbor(&ipc::Reply::Ok(observation(request))).unwrap(),&limits()).unwrap();
        }
        server.set_nonblocking(false).unwrap();server.set_read_timeout(Some(PROBE)).unwrap();let mut byte=[0;1];assert_eq!(server.read(&mut byte).unwrap(),0);
    });
    let end=Instant::now()+PROBE;let valid=AtomicBool::new(true);
    let calls=std::sync::atomic::AtomicUsize::new(0);let failed=AtomicBool::new(false);
    {
        let guard=SelectedReadinessIoGuard::fixture(end,&valid,&calls,&failed);
        let mut operation=ReadinessOperation {guard,stream:&mut stream,armed:true};
        let mut instance=None;
        exchange_owned(&mut operation,&binding(),&mut instance,end).unwrap();
        exchange_owned(&mut operation,&binding(),&mut instance,end).unwrap();
        assert!(operation.armed);assert_eq!(instance,Some([7;32]));
        assert!(!failed.load(Ordering::SeqCst));
        // A surrounding original assignment failure still vetoes both fully
        // received inner exchanges before the connection can be reused.
    }
    assert!(failed.load(Ordering::SeqCst));assert!(!valid.load(Ordering::SeqCst));
    assert!(stream.is_none());worker.join().unwrap();
}

#[test]
fn readiness_frame_caps_preserve_existing_separate_two_second_budget_and_original_end() {
    let valid=AtomicBool::new(true);let calls=std::sync::atomic::AtomicUsize::new(0);let failed=AtomicBool::new(false);
    let short=Instant::now()+Duration::from_millis(100);
    let guard=SelectedReadinessIoGuard::fixture(short,&valid,&calls,&failed);
    assert_eq!(guard.frame_end(short).unwrap(),short);
    let original=Instant::now()+Duration::from_secs(10);
    let guard=SelectedReadinessIoGuard::fixture(original,&valid,&calls,&failed);
    let before=Instant::now();let write=guard.frame_end(original).unwrap();let after=Instant::now();
    assert!(write>=before+PROBE && write<=after+PROBE && write<original);
    let reply=guard.frame_end(original).unwrap();assert!(reply>=write && reply<original);
    assert!(guard.frame_end(original+PROBE).is_err());
}


fn retained_assignment(valid:Arc<AtomicBool>,panic:Arc<AtomicBool>,reads:Arc<std::sync::atomic::AtomicUsize>,
    drops:Arc<std::sync::atomic::AtomicUsize>)->FixtureReadinessAssignment {
    FixtureReadinessAssignment {valid,panic,reads,drops}
}

#[test]
fn readiness_native_and_fixture_share_exact_negative_phase_matrix_and_retained_readback_engine() {
    for owned in [false,true] {for initial in [false,true] {for phase in [ReadinessPhase::Connect,ReadinessPhase::InitialProbe,ReadinessPhase::AssignedProbe,ReadinessPhase::Assignment] {
        let expected=match phase {
            ReadinessPhase::Connect|ReadinessPhase::InitialProbe=>!owned && !initial,
            ReadinessPhase::AssignedProbe=>owned && initial,
            ReadinessPhase::Assignment=>initial,
        };
        let live=Arc::new(AtomicBool::new(true));let panic=Arc::new(AtomicBool::new(false));
        let reads=Arc::new(std::sync::atomic::AtomicUsize::new(0));let drops=Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut state=TaskAssignment::new();state.initial_observed=initial;
        if owned {state.owner=Some(retained_assignment(live,panic,reads.clone(),drops.clone()));}
        let (client,mut peer)=UnixStream::pair().unwrap();let mut stream=Some(client);
        let end=Instant::now()+PROBE;let valid=AtomicBool::new(true);
        let calls=std::sync::atomic::AtomicUsize::new(0);let failed=AtomicBool::new(false);
        {
            let mut guard=SelectedReadinessIoGuard::fixture(end,&valid,&calls,&failed);
            guard.assignment=ReadinessAssignment::Fixture(&mut state);guard.phase=phase;
            let mut operation=ReadinessOperation {guard,stream:&mut stream,armed:true};
            assert_eq!(operation.current().is_ok(),expected);
            if expected {operation.complete();}
        }
        assert_eq!(state.owner.is_some(),owned);assert_eq!(drops.load(Ordering::SeqCst),0);
        assert_eq!(reads.load(Ordering::SeqCst),if expected && owned {2}else{0});
        if !expected {
            use std::io::Read;assert!(failed.load(Ordering::SeqCst) && state.poisoned && stream.is_none());
            assert_eq!(peer.read(&mut[0;1]).unwrap(),0);
        }
        drop(state);assert_eq!(drops.load(Ordering::SeqCst),usize::from(owned));
    }}}
}

#[test]
fn readiness_shared_initial_assignment_followup_flow_keeps_original_owner_and_outer_veto_until_final_result() {
    use std::io::Read;
    let (client,mut server)=UnixStream::pair().unwrap();let mut stream=Some(client);
    let worker=std::thread::spawn(move|| {
        for _ in 0..2 {
            let request=strict_decode::<Request>(&ipc::read_frame_timed(&mut server,&limits()).unwrap()).unwrap();
            ipc::write_frame_timed(&mut server,&ipc::to_cbor(&ipc::Reply::Ok(observation(request))).unwrap(),&limits()).unwrap();
        }
        server.set_nonblocking(false).unwrap();server.set_read_timeout(Some(PROBE)).unwrap();assert_eq!(server.read(&mut[0;1]).unwrap(),0);
    });
    let end=Instant::now()+PROBE;let valid=AtomicBool::new(true);
    let calls=std::sync::atomic::AtomicUsize::new(0);let failed=AtomicBool::new(false);
    let live=Arc::new(AtomicBool::new(true));let panic=Arc::new(AtomicBool::new(false));
    let reads=Arc::new(std::sync::atomic::AtomicUsize::new(0));let drops=Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut state=TaskAssignment::<FixtureReadinessAssignment>::new();let mut instance=None;
    {
        let mut guard=SelectedReadinessIoGuard::fixture(end,&valid,&calls,&failed);
        guard.assignment=ReadinessAssignment::Fixture(&mut state);
        let mut operation=ReadinessOperation {guard,stream:&mut stream,armed:true};
        exchange_owned(&mut operation,&binding(),&mut instance,end).unwrap();operation.guard.complete_probe().unwrap();
        operation.guard.phase=ReadinessPhase::Assignment;operation.current().unwrap();
        if let ReadinessAssignment::Fixture(state)=&mut operation.guard.assignment {
            state.assign(end,|_|Ok(retained_assignment(live,panic,reads.clone(),drops.clone()))).unwrap();
        }
        operation.current().unwrap();operation.guard.phase=ReadinessPhase::AssignedProbe;
        exchange_owned(&mut operation,&binding(),&mut instance,end).unwrap();operation.current().unwrap();
        operation.guard.complete_probe().unwrap();assert!(operation.armed);operation.complete();
    }
    assert!(!failed.load(Ordering::SeqCst));assert!(stream.is_some() && state.owner.is_some());
    assert!(state.initial_observed && reads.load(Ordering::SeqCst)>4);assert_eq!(drops.load(Ordering::SeqCst),0);
    // A second assignment is refused under the SAME outer engine, without
    // dropping or replacing the original retained assignment owner.
    {
        let mut guard=SelectedReadinessIoGuard::fixture(end,&valid,&calls,&failed);
        guard.assignment=ReadinessAssignment::Fixture(&mut state);guard.phase=ReadinessPhase::Assignment;
        let mut operation=ReadinessOperation {guard,stream:&mut stream,armed:true};operation.current().unwrap();
        if let ReadinessAssignment::Fixture(state)=&mut operation.guard.assignment {
            assert!(state.assign(end,|_|panic!("REPLACEMENT_ASSIGNMENT_CONSTRUCTOR")).is_err());
        }
    }
    assert!(failed.load(Ordering::SeqCst) && state.poisoned && stream.is_none());
    assert_eq!(drops.load(Ordering::SeqCst),0);drop(state);assert_eq!(drops.load(Ordering::SeqCst),1);worker.join().unwrap();
}

#[test]
fn readiness_shared_assignment_readback_loss_unwind_and_late_constructor_preserve_original_until_veto_then_drop() {
    use std::io::Read;
    for mode in ["loss","unwind","late-constructor"] {
        let end=Instant::now()+if mode=="late-constructor" {Duration::from_millis(20)}else{PROBE};
        let valid=AtomicBool::new(true);let calls=std::sync::atomic::AtomicUsize::new(0);let failed=AtomicBool::new(false);
        let live=Arc::new(AtomicBool::new(mode!="loss"));let panic=Arc::new(AtomicBool::new(mode=="unwind"));
        let reads=Arc::new(std::sync::atomic::AtomicUsize::new(0));let drops=Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut state=TaskAssignment::new();state.initial_observed=true;
        if mode!="late-constructor" {state.owner=Some(retained_assignment(live.clone(),panic.clone(),reads.clone(),drops.clone()));}
        let (client,mut server)=UnixStream::pair().unwrap();let mut stream=Some(client);
        let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||->EnclaveResult<()> {
            let mut guard=SelectedReadinessIoGuard::fixture(end,&valid,&calls,&failed);
            guard.assignment=ReadinessAssignment::Fixture(&mut state);
            guard.phase=if mode=="late-constructor" {ReadinessPhase::Assignment}else{ReadinessPhase::AssignedProbe};
            let mut operation=ReadinessOperation {guard,stream:&mut stream,armed:true};operation.current()?;
            if let ReadinessAssignment::Fixture(state)=&mut operation.guard.assignment {
                state.assign(end,|_| {
                    std::thread::sleep(Duration::from_millis(40));
                    Ok(retained_assignment(live.clone(),panic.clone(),reads.clone(),drops.clone()))
                })?;
            }
            operation.current()?;operation.complete();Ok(())
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert!(failed.load(Ordering::SeqCst) && state.poisoned && stream.is_none());
        assert!(state.owner.is_some());assert_eq!(drops.load(Ordering::SeqCst),0);
        assert_eq!(server.read(&mut[0;1]).unwrap(),0);
        live.store(true,Ordering::SeqCst);panic.store(false,Ordering::SeqCst);
        let mut guard=SelectedReadinessIoGuard::fixture(end,&valid,&calls,&failed);
        guard.assignment=ReadinessAssignment::Fixture(&mut state);guard.phase=ReadinessPhase::AssignedProbe;
        assert!(guard.current(end,None).is_err());drop(guard);
        assert_eq!(drops.load(Ordering::SeqCst),0);drop(state);assert_eq!(drops.load(Ordering::SeqCst),1);
    }
}


// SOFTWARE lifecycle fixtures only: they cannot create native PF/session
// objects or manufacture readiness terms. The production sequencing is shared.
struct ReadOnlyPfFixture {
    identity:Arc<()>,live:Arc<AtomicBool>,stop:Arc<AtomicBool>,end:Instant,
    terminal:AtomicBool,behavior:std::sync::atomic::AtomicUsize,
    ends:Mutex<Vec<Instant>>,events:Arc<Mutex<Vec<&'static str>>>,
    during_health:Option<Box<dyn FnMut()>>,
}
impl ReadOnlyPfDependency<SessionFixture> for ReadOnlyPfFixture {
    fn require_original(&self,session:&SessionFixture,stop:&Arc<AtomicBool>,end:Instant)->EnclaveResult<()> {
        self.events.lock().unwrap().push("readonly-pf-binding");
        if !Arc::ptr_eq(&session.live,&self.live) || !Arc::ptr_eq(stop,&self.stop) || end>self.end
            || self.terminal.load(Ordering::SeqCst) {
            self.veto();fail!(EACCES,"FIXTURE_READONLY_PF_BINDING");
        }
        Ok(())
    }
    fn require_health_until<C:super::super::pf_watch::NegativeCollectionCheck>(&mut self,end:Instant,collection:&C)->EnclaveResult<()> {
        collection.require_current(end)?;
        self.events.lock().unwrap().push("readonly-pf-health");self.ends.lock().unwrap().push(end);
        if let Some(during)=&mut self.during_health {during();}
        match self.behavior.load(Ordering::SeqCst) {
            1=>Err(err!(EIO,"FIXTURE_READONLY_PF_FAILED")),
            2=>panic!("fixture PF collection unwind"),
            3=>{self.live.store(false,Ordering::SeqCst);Ok(())},
            _=>Ok(()),
        }
    }
    fn veto(&self) {
        self.live.store(false,Ordering::SeqCst);self.stop.store(true,Ordering::SeqCst);
        self.terminal.store(true,Ordering::SeqCst);self.events.lock().unwrap().push("readonly-pf-veto");
    }
}
impl Drop for ReadOnlyPfFixture {
    fn drop(&mut self) {
        assert!(!self.live.load(Ordering::SeqCst) && self.stop.load(Ordering::SeqCst)
            && self.terminal.load(Ordering::SeqCst),"all original vetoes must precede PF owner cleanup");
        self.events.lock().unwrap().push("readonly-pf-drop");
    }
}
fn readonly_pf_fixture(lifetime:&SessionLifetime<SessionFixture>)->ReadOnlyPfFixture {
    ReadOnlyPfFixture {identity:Arc::new(()),live:lifetime.session.live.clone(),stop:lifetime.stop.clone(),
        end:lifetime.end,terminal:AtomicBool::new(false),behavior:std::sync::atomic::AtomicUsize::new(0),
        ends:Mutex::new(Vec::new()),events:lifetime.session.events.clone(),during_health:None}
}
#[test]
fn retained_readonly_pf_handoff_and_samples_keep_same_owner_and_only_shorten_original_cap() {
    let (lifetime,events)=session_fixture();let notification=notification_fixture(&lifetime);let mut slot=PreparedSlot::empty();
    slot.construct(&lifetime,|_|Ok(readonly_pf_fixture(&lifetime))).unwrap();
    let identity=slot.owner.as_ref().unwrap().identity.clone();let short=Instant::now()+Duration::from_secs(1);
    require_readonly_pf(&lifetime,&notification,slot.get(),short).unwrap();let mut handed=slot.take();
    require_readonly_pf(&lifetime,&notification,&mut handed,lifetime.end+PROBE).unwrap();
    assert!(Arc::ptr_eq(&identity,&handed.identity));assert_eq!(*handed.ends.lock().unwrap(),[short,lifetime.end]);
    assert_eq!(handed.end,lifetime.end);assert!(lifetime.session.live.load(Ordering::SeqCst));
    {
        let _guard=ReadOnlyPfCleanup {session:&lifetime.session,stop:&lifetime.stop,pf:&mut handed,armed:true};
    }
    drop(handed);let events=events.lock().unwrap();
    assert!(events.iter().position(|e|*e=="revoke").unwrap()<events.iter().position(|e|*e=="readonly-pf-drop").unwrap());
    assert!(events.iter().position(|e|*e=="readonly-pf-veto").unwrap()<events.iter().position(|e|*e=="readonly-pf-drop").unwrap());
}
#[test]
fn retained_readonly_pf_failure_unwind_or_postcheck_loss_vetoes_all_originals_and_forbids_retry() {
    for behavior in [1,2,3] {
        let (lifetime,events)=session_fixture();let mut pf=readonly_pf_fixture(&lifetime);let notification=notification_fixture(&lifetime);
        pf.behavior.store(behavior,Ordering::SeqCst);
        let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||require_readonly_pf(&lifetime,&notification,&mut pf,lifetime.end)));
        if behavior==2 {assert!(result.is_err());}else{assert!(result.unwrap().is_err());}
        assert!(!lifetime.session.live.load(Ordering::SeqCst) && lifetime.stop.load(Ordering::SeqCst)
            && pf.terminal.load(Ordering::SeqCst));
        pf.behavior.store(0,Ordering::SeqCst);lifetime.stop.store(false,Ordering::SeqCst);
        assert!(require_readonly_pf(&lifetime,&notification,&mut pf,lifetime.end).is_err());assert_eq!(pf.ends.lock().unwrap().len(),1);
        events.lock().unwrap().push("other-native-drop");drop(pf);
        let events=events.lock().unwrap();
        assert!(events.iter().position(|e|*e=="readonly-pf-veto").unwrap()<events.iter().position(|e|*e=="other-native-drop").unwrap());
    }
}
#[test]
fn retained_readonly_pf_foreign_session_stop_or_longer_outer_binding_refuses_before_health() {
    for mismatch in [0,1,2] {
        let (original,_)=session_fixture();let mut pf=readonly_pf_fixture(&original);let notification=notification_fixture(&original);
        let (mut offered,_)=session_fixture();
        if mismatch!=0 {offered.session.live=original.session.live.clone();}
        if mismatch!=1 {offered.stop=original.stop.clone();}
        offered.end=if mismatch==2 {original.end+PROBE}else{original.end};
        assert!(require_readonly_pf(&offered,&notification,&mut pf,offered.end).is_err());assert!(pf.ends.lock().unwrap().is_empty());
        assert!(!original.session.live.load(Ordering::SeqCst) && original.stop.load(Ordering::SeqCst));
        assert!(!offered.session.live.load(Ordering::SeqCst) && offered.stop.load(Ordering::SeqCst));drop(pf);
    }
}
#[test]
fn retained_readonly_pf_expired_cap_refuses_before_collection_and_outer_unwind_vetoes_before_drop() {
    let (lifetime,events)=session_fixture();let mut pf=readonly_pf_fixture(&lifetime);let notification=notification_fixture(&lifetime);
    assert!(require_readonly_pf(&lifetime,&notification,&mut pf,Instant::now()).is_err());assert!(pf.ends.lock().unwrap().is_empty());
    assert!(pf.terminal.load(Ordering::SeqCst));drop(pf);
    let (lifetime,_)=session_fixture();let mut pf=readonly_pf_fixture(&lifetime);let notification=notification_fixture(&lifetime);
    require_readonly_pf(&lifetime,&notification,&mut pf,lifetime.end).unwrap();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(||{
        let _guard=ReadOnlyPfCleanup {session:&lifetime.session,stop:&lifetime.stop,pf:&mut pf,armed:true};
        panic!("later non-PF readiness sample unwind");
    })).is_err());
    assert!(!lifetime.session.live.load(Ordering::SeqCst) && lifetime.stop.load(Ordering::SeqCst)
        && pf.terminal.load(Ordering::SeqCst));drop(pf);
    assert!(events.lock().unwrap().contains(&"readonly-pf-veto"));
}
#[test]
fn retained_readonly_pf_partial_return_is_held_until_session_and_pf_veto_before_cleanup() {
    let (lifetime,events)=session_fixture();let mut slot=PreparedSlot::empty();
    assert!(slot.construct(&lifetime,|_|{
        let pf=readonly_pf_fixture(&lifetime);lifetime.session.live.store(false,Ordering::SeqCst);Ok(pf)
    }).is_err());
    assert!(slot.owner.is_some());assert!(!events.lock().unwrap().contains(&"readonly-pf-drop"));
    assert!(slot.construct(&lifetime,|_|panic!("partial original was reopened")).is_err());
    slot.owner.as_ref().unwrap().veto();drop(slot);
    let events=events.lock().unwrap();assert!(events.iter().position(|e|*e=="revoke").unwrap()
        <events.iter().position(|e|*e=="readonly-pf-drop").unwrap());
}

// SOFTWARE notification window: borrows its original fixture owner and shares
// its sticky veto; never creates native registration/continuity authority.
struct NotificationCollectionFixture<'a> {owner:&'a NotificationFixture,generation:u64,end:Instant,armed:bool}
impl super::super::pf_watch::NegativeCollectionCheck for NotificationCollectionFixture<'_> {
    fn require_current(&self,end:Instant)->EnclaveResult<()> {
        self.owner.events.lock().unwrap().push("notification-collection-current");
        if !self.owner.live.load(Ordering::SeqCst) || self.owner.stop.load(Ordering::SeqCst)
            || self.owner.collection_generation.load(Ordering::SeqCst)!=self.generation
            || Instant::now()>=end.min(self.end) {
            self.owner.request_stop();fail!(EACCES,"FIXTURE_NOTIFICATION_COLLECTION_CHANGED");
        }
        Ok(())
    }
    fn require_same_original(&self,_session:&Arc<crate::power::selected_owner_session::SelectedOwnerSession>,
        _stop:&Arc<AtomicBool>,_end:Instant)->EnclaveResult<()> {
        Err(err!(EACCES,"FIXTURE_CANNOT_BIND_NATIVE_COLLECTION"))
    }
    fn complete(mut self,end:Instant)->EnclaveResult<()> {
        super::super::pf_watch::NegativeCollectionCheck::require_current(&self,end)?;
        self.owner.events.lock().unwrap().push("notification-collection-complete");
        self.armed=false;Ok(())
    }
}
impl Drop for NotificationCollectionFixture<'_> {
    fn drop(&mut self){if self.armed {self.owner.request_stop();}}
}
#[test]
fn readonly_pf_mandatory_window_fresh_challenge_spans_health_and_same_original_postchecks() {
    let (lifetime,events)=session_fixture();let notification=notification_fixture(&lifetime);let mut pf=readonly_pf_fixture(&lifetime);
    require_readonly_pf(&lifetime,&notification,&mut pf,lifetime.end).unwrap();
    let observed=events.lock().unwrap();
    let fresh=observed.iter().position(|event|*event=="notification-progress").unwrap();
    let health=observed.iter().position(|event|*event=="readonly-pf-health").unwrap();
    let completed=observed.iter().position(|event|*event=="notification-collection-complete").unwrap();
    assert!(fresh<health && health<completed);
    assert!(observed[health+1..completed].contains(&"notification-binding"));
    assert_eq!(observed.iter().filter(|event|**event=="notification-progress").count(),1);
    drop(observed);pf.veto();notification.request_stop();drop(pf);drop(notification);
}
#[test]
fn readonly_pf_mandatory_window_begin_refusal_or_unwind_prevents_health_and_vetoes_both_owners() {
    for behavior in [1,2] {
        let (lifetime,_)=session_fixture();let notification=notification_fixture(&lifetime);let mut pf=readonly_pf_fixture(&lifetime);
        notification.progress_behavior.store(behavior,Ordering::SeqCst);
        let outcome=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
            require_readonly_pf(&lifetime,&notification,&mut pf,lifetime.end)));
        if behavior==2 {assert!(outcome.is_err());}else{assert!(outcome.unwrap().is_err());}
        assert!(pf.ends.lock().unwrap().is_empty());
        assert!(!lifetime.session.live.load(Ordering::SeqCst) && lifetime.stop.load(Ordering::SeqCst));
        assert!(pf.terminal.load(Ordering::SeqCst));drop(pf);drop(notification);
    }
}
#[test]
fn readonly_pf_mandatory_window_generation_loss_after_health_cannot_complete_or_retry() {
    let (lifetime,events)=session_fixture();let notification=notification_fixture(&lifetime);let mut pf=readonly_pf_fixture(&lifetime);
    let changed=notification.collection_generation.clone();
    pf.during_health=Some(Box::new(move||{changed.fetch_add(1,Ordering::SeqCst);}));
    assert!(require_readonly_pf(&lifetime,&notification,&mut pf,lifetime.end).is_err());
    assert_eq!(pf.ends.lock().unwrap().len(),1);assert!(pf.terminal.load(Ordering::SeqCst));
    assert!(!lifetime.session.live.load(Ordering::SeqCst) && lifetime.stop.load(Ordering::SeqCst));
    assert!(!events.lock().unwrap().contains(&"notification-collection-complete"));
    pf.during_health=None;
    assert!(require_readonly_pf(&lifetime,&notification,&mut pf,lifetime.end).is_err());
    assert_eq!(pf.ends.lock().unwrap().len(),1);drop(pf);drop(notification);
}
