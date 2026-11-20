// SOFTWARE fixtures over the actual role dispatcher, framing, descriptor
// transport, durable idle reader and marker implementation. Authentication and
// checked process selection are injected here, never claimed as native proof.
use super::*;
use std::{cell::Cell,net::Shutdown,os::unix::fs::symlink};

fn binding() -> AdminBinding {
    AdminBinding {target_id:"selected-admin-fixture".into(),descriptor_sha256:"ab".repeat(32),pins_sha256:"cd".repeat(32)}
}
fn request() -> AdminRequest {
    AdminRequest {v:1,action:AdminAction::QuiesceIdle,binding:binding(),challenge:[19;32]}
}
fn durable(f:&Fixture) -> BTreeMap<&'static str,Vec<u8>> {
    ["sealing.key","apfs-publications.sealed","apfs-publications.gen"].into_iter()
        .map(|name|(name,std::fs::read(f.paths.state().join(name)).unwrap())).collect()
}
fn marker(f:&Fixture) -> PathBuf {f.paths.base.join("deployment.quiesced")}
fn wire(broker:&mut Broker,bytes:&[u8],fds:&[i32],extra:&[u8],
    check:impl Fn(&AdminBinding)->EnclaveResult<()>) -> EnclaveResult<ipc::Reply<AdminResponse>> {
    let (server,mut client)=UnixStream::pair().unwrap();
    ipc::write_frame(&mut client,bytes).unwrap();ipc::send_fd_packet(&client,fds).unwrap();
    client.write_all(extra).unwrap();client.shutdown(Shutdown::Write).unwrap();
    connection_for_role(server,broker,|_|Ok(PeerRole::Maintenance(binding())),check)?;
    let until=Instant::now()+Duration::from_secs(2);
    let reply=decode_admin(&bounded_frame_before(&mut client,until)?)?;
    ipc::recv_fd_packet(&client,0)?;admin_eof(&mut client,until)?;Ok(reply)
}
fn roundtrip(broker:&mut Broker,check:impl Fn(&AdminBinding)->EnclaveResult<()>) -> EnclaveResult<ipc::Reply<AdminResponse>> {
    wire(broker,&ipc::to_cbor(&request()).unwrap(),&[],&[],check)
}
fn refused(reply:ipc::Reply<AdminResponse>,reason:&str) {
    let ipc::Reply::Err(error)=reply else {panic!("administrative operation unexpectedly admitted")};
    assert!(error.is(reason));assert!(error.detail.is_empty());
}

#[test]
fn live_admin_success_preserves_all_durable_state_and_blocks_later_cas() {
    let f=Fixture::new("");let mut broker=f.broker();let before=durable(&f);let calls=Cell::new(0);
    let reply=roundtrip(&mut broker,|actual| {assert_eq!(actual,&binding());calls.set(calls.get()+1);Ok(())}).unwrap();
    let ipc::Reply::Ok(reply)=reply else {panic!("expected restrictive acknowledgement")};
    assert_eq!(reply.binding,binding());assert_eq!(reply.challenge,request().challenge);assert_eq!(calls.get(),2);
    assert_eq!(std::fs::read(marker(&f)).unwrap(),b"1\n");assert!(durable(&f)==before);
    assert!(f.publish(&mut broker).unwrap_err().is("BROKER_QUIESCED"));
    assert!(f.platform.calls.lock().unwrap().is_empty());
}
#[test]
fn actual_admin_client_and_server_transport_complete_the_same_one_shot_wire() {
    let f=Fixture::new("");let mut broker=f.broker();let before=durable(&f);
    let (server,mut client)=UnixStream::pair().unwrap();
    let thread=std::thread::spawn(move||connection_for_role(server,&mut broker,
        |_|Ok(PeerRole::Maintenance(binding())),|_|Ok(())));
    admin_exchange(&mut client,&request(),Instant::now()+Duration::from_secs(2)).unwrap();
    thread.join().unwrap().unwrap();assert!(durable(&f)==before);assert_eq!(std::fs::read(marker(&f)).unwrap(),b"1\n");
}
#[test]
fn root_role_cannot_dispatch_any_cas_operation() {
    let f=Fixture::new("");let mut broker=f.broker();let before=durable(&f);
    for request in [Request::Publish{root:f.root_hash()},Request::Reopen{root:f.root_hash()},
        Request::Revoke{root:f.root_hash()},Request::Prepare{root:f.root_hash()}] {
        assert!(wire(&mut broker,&ipc::to_cbor(&request).unwrap(),&[],&[],|_|Ok(())).is_err());
        assert!(!marker(&f).exists());assert!(durable(&f)==before);
    }
    assert!(f.platform.calls.lock().unwrap().is_empty());
}
#[test]
fn cas_role_cannot_dispatch_admin_and_old_protocol_client_refuses() {
    let f=Fixture::new("");let mut broker=f.broker();let (server,mut client)=UnixStream::pair().unwrap();
    let thread=std::thread::spawn(move||connection(server,&mut broker,|_|Ok(())));
    assert!(admin_exchange(&mut client,&request(),Instant::now()+Duration::from_secs(2)).is_err());
    assert!(thread.join().unwrap().is_err());assert!(!marker(&f).exists());
}
#[test]
fn failed_authentication_precedes_all_request_and_rights_reads() {
    let f=Fixture::new("");let mut broker=f.broker();let (server,_client)=UnixStream::pair().unwrap();
    let begin=Instant::now();
    assert!(connection_for_role(server,&mut broker,|_|Err(err!(EACCES,"SYNTHETIC_AUDIT_DENIAL")),
        |_|panic!("no administrative recheck before authentication")).unwrap_err().is("SYNTHETIC_AUDIT_DENIAL"));
    assert!(begin.elapsed()<Duration::from_secs(1));assert!(!marker(&f).exists());
}
#[test]
fn wrong_target_descriptor_pins_and_version_refuse_before_idle_effects() {
    for field in 0..4 {
        let f=Fixture::new("");let mut broker=f.broker();let before=durable(&f);let mut request=request();
        match field {0=>request.binding.target_id.push('x'),1=>request.binding.descriptor_sha256="ef".repeat(32),
            2=>request.binding.pins_sha256="ef".repeat(32),_=>request.v=2}
        refused(wire(&mut broker,&ipc::to_cbor(&request).unwrap(),&[],&[],|_|panic!("binding must refuse first")).unwrap(),"BROKER_ADMIN_BINDING");
        assert!(!marker(&f).exists());assert!(durable(&f)==before);
    }
}
#[test]
fn unknown_fields_actions_cbor_trailing_and_stream_trailing_are_inert() {
    let f=Fixture::new("");let mut broker=f.broker();let before=durable(&f);
    let value=serde_json::to_value(request()).unwrap();
    let mut extra=value.clone();extra["restore_state"]=serde_json::json!(true);
    let mut action=value;action["action"]=serde_json::json!("Revoke");
    let mut trailing=ipc::to_cbor(&request()).unwrap();trailing.push(0);
    for bytes in [ipc::to_cbor(&extra).unwrap(),ipc::to_cbor(&action).unwrap(),trailing,vec![0;FRAME+1]] {
        assert!(wire(&mut broker,&bytes,&[],&[],|_|Ok(())).is_err());
    }
    assert!(wire(&mut broker,&ipc::to_cbor(&request()).unwrap(),&[],b"late second request",|_|Ok(())).unwrap_err().is("BROKER_ADMIN_TRAILING"));
    assert!(!marker(&f).exists());assert!(durable(&f)==before);
}
#[test]
fn any_unexpected_descriptor_is_closed_without_operation_or_sentinel_damage() {
    let f=Fixture::new("");let mut broker=f.broker();let file=f.stage(b"unrelated sentinel");
    assert!(wire(&mut broker,&ipc::to_cbor(&request()).unwrap(),&[file.as_raw_fd()],&[],|_|Ok(())).is_err());
    assert!(unsafe{libc::fcntl(file.as_raw_fd(),libc::F_GETFD)}>=0);
    assert!(!marker(&f).exists());assert!(f.platform.calls.lock().unwrap().is_empty());
}
#[test]
fn missing_explicit_zero_rights_packet_cannot_be_a_success() {
    let f=Fixture::new("");let mut broker=f.broker();let (server,mut client)=UnixStream::pair().unwrap();
    ipc::write_frame(&mut client,&ipc::to_cbor(&request()).unwrap()).unwrap();client.shutdown(Shutdown::Write).unwrap();
    assert!(connection_for_role(server,&mut broker,|_|Ok(PeerRole::Maintenance(binding())),|_|Ok(())).is_err());
    assert!(!marker(&f).exists());
}
#[test]
fn accepted_lock_covers_auth_both_binding_checks_and_marker_acknowledgement() {
    let f=Fixture::new("");let mut broker=f.broker();let (server,mut client)=UnixStream::pair().unwrap();
    ipc::write_frame(&mut client,&ipc::to_cbor(&request()).unwrap()).unwrap();ipc::send_fd_packet(&client,&[]).unwrap();client.shutdown(Shutdown::Write).unwrap();
    let check_lock=|| {
        let Err(error)=Operation::acquire(operation_file(&f.paths,ipc::geteuid()).unwrap()) else {panic!("accepted operation lock was not retained")};
        assert!(error.is("BROKER_OPERATION_BUSY"));
    };
    connection_for_role(server,&mut broker,|_| {check_lock();Ok(PeerRole::Maintenance(binding()))},
        |_| {check_lock();Ok(())}).unwrap();
    assert!(Operation::acquire(operation_file(&f.paths,ipc::geteuid()).unwrap()).is_ok());
}
#[test]
fn contention_prevents_authentication_and_marker_creation() {
    let f=Fixture::new("");let mut broker=f.broker();
    let _busy=Operation::acquire(operation_file(&f.paths,ipc::geteuid()).unwrap()).unwrap();
    let (server,_client)=UnixStream::pair().unwrap();
    assert!(connection_for_role(server,&mut broker,|_|panic!("busy must refuse before auth"),|_|Ok(())).unwrap_err().is("BROKER_OPERATION_BUSY"));
    assert!(!marker(&f).exists());
}
#[test]
fn in_memory_poison_or_stage_intent_blocks_even_when_durable_state_is_empty() {
    for poisoned in [false,true] {
        let f=Fixture::new("");let mut broker=f.broker();let before=durable(&f);
        if poisoned {broker.poisoned=true;}else{broker.state.stage_intent=Some(f.config.clone());}
        refused(roundtrip(&mut broker,|_|Ok(())).unwrap(),if poisoned {"BROKER_STATE_RESTART_REQUIRED"}else{"BROKER_PUBLICATIONS_REQUIRE_RETRACTION"});
        assert!(!marker(&f).exists());assert!(durable(&f)==before);assert!(f.platform.calls.lock().unwrap().is_empty());
    }
}
#[test]
fn durable_nonempty_ownership_blocks_even_if_memory_was_emptied() {
    let f=Fixture::new("");let mut broker=f.broker();drop(f.publish(&mut broker).unwrap());
    let before=durable(&f);let calls=f.platform.calls.lock().unwrap().clone();broker.state.records.clear();
    refused(roundtrip(&mut broker,|_|Ok(())).unwrap(),"BROKER_PUBLICATIONS_REQUIRE_RETRACTION");
    assert!(durable(&f)==before);assert_eq!(*f.platform.calls.lock().unwrap(),calls);assert!(!marker(&f).exists());
}
#[test]
fn missing_required_files_are_never_initialized_by_live_inspection() {
    for name in ["sealing.key","apfs-publications.sealed","apfs-publications.gen"] {
        let f=Fixture::new("");let mut broker=f.broker();let path=f.paths.state().join(name);std::fs::remove_file(&path).unwrap();
        refused(roundtrip(&mut broker,|_|Ok(())).unwrap(),"BROKER_FILE");assert!(!path.exists());assert!(!marker(&f).exists());
    }
}
#[test]
fn current_pin_requirements_are_exact_nonempty_and_never_team_only_or_union() {
    let id=enclave_core::codesign::CTL_IDENTIFIER;let old="ab".repeat(20);let fresh="cd".repeat(20);
    let mut manifest=BTreeMap::from([(id.to_string(),vec![old.clone()])]);
    let first=current_requirement(id,&manifest).unwrap();manifest.insert(id.into(),vec![fresh.clone()]);
    let rotated=current_requirement(id,&manifest).unwrap();assert_eq!(rotated.cdhash_allowlist,vec![fresh.clone()]);
    let identity=|hash:&str|enclave_core::codesign::CodeIdentity {identifier:id.into(),team_id:enclave_core::codesign::TEAM_ID.into(),cdhash:hash.into()};
    assert!(first.matches(&identity(&old)));assert!(!rotated.matches(&identity(&old)));assert!(rotated.matches(&identity(&fresh)));
    let mut foreign=identity(&fresh);foreign.identifier="com.foreign.ctl".into();assert!(!rotated.matches(&foreign));
    foreign=identity(&fresh);foreign.team_id="FOREIGNTEAM".into();assert!(!rotated.matches(&foreign));
    for hashes in [vec![],vec!["short".into()],vec![old.clone(),old.to_ascii_uppercase()],vec![old;33]] {
        manifest.insert(id.into(),hashes);assert!(current_requirement(id,&manifest).is_err());
    }
    assert!(current_requirement(id,&BTreeMap::new()).is_err());
}
#[test]
fn pin_or_context_change_before_marker_is_inert_and_after_marker_is_failure() {
    for fail_at in [1,2] {
        let f=Fixture::new("");let mut broker=f.broker();let before=durable(&f);let checks=Cell::new(0);
        refused(roundtrip(&mut broker,|_| {checks.set(checks.get()+1);
            if checks.get()==fail_at {Err(err!(ESTALE,"SYNTHETIC_CURRENT_PINS_CHANGED"))}else{Ok(())}
        }).unwrap(),"SYNTHETIC_CURRENT_PINS_CHANGED");
        assert_eq!(marker(&f).exists(),fail_at==2);assert!(durable(&f)==before);
    }
}
#[test]
fn lost_reply_leaves_restrictive_marker_and_never_replays_effects() {
    let f=Fixture::new("");let mut broker=f.broker();let before=durable(&f);let (server,mut client)=UnixStream::pair().unwrap();
    ipc::write_frame(&mut client,&ipc::to_cbor(&request()).unwrap()).unwrap();ipc::send_fd_packet(&client,&[]).unwrap();
    client.shutdown(Shutdown::Both).unwrap();
    assert!(connection_for_role(server,&mut broker,|_|Ok(PeerRole::Maintenance(binding())),|_|Ok(())).is_err());
    assert_eq!(std::fs::read(marker(&f)).unwrap(),b"1\n");assert!(durable(&f)==before);
    assert!(f.publish(&mut broker).unwrap_err().is("BROKER_QUIESCED"));
}
#[test]
fn invalid_existing_marker_types_bytes_modes_and_links_never_get_repaired() {
    for case in 0..7 {
        let f=Fixture::new("");let _broker=f.broker();let path=marker(&f);
        match case {
            0=>std::fs::write(&path,b"").unwrap(),1=>std::fs::write(&path,b"1").unwrap(),
            2=>std::fs::write(&path,b"x\n").unwrap(),
            3=>{std::fs::write(&path,b"1\n").unwrap();std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o644)).unwrap();},
            4=>{std::fs::write(&path,b"1\n").unwrap();std::fs::hard_link(&path,f.root.join("alias")).unwrap();},
            5=>{std::fs::write(f.root.join("outside"),b"1\n").unwrap();symlink(f.root.join("outside"),&path).unwrap();},
            _=>{use std::os::unix::ffi::OsStrExt;let name=std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();assert_eq!(unsafe{libc::mkfifo(name.as_ptr(),0o600)},0);},
        }
        if case<3||case==4 {std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o600)).unwrap();}
        let before=std::fs::symlink_metadata(&path).unwrap();assert!(quiesce(&f.paths,ipc::geteuid()).is_err());
        let after=std::fs::symlink_metadata(&path).unwrap();assert_eq!((before.dev(),before.ino(),before.len(),before.mode(),before.nlink()),(after.dev(),after.ino(),after.len(),after.mode(),after.nlink()));
    }
}
#[test]
fn both_new_and_existing_exact_marker_receive_file_and_parent_sync() {
    let f=Fixture::new("");let _broker=f.broker();
    for _ in 0..2 {let calls=Cell::new(0);
        publish_quiescence_marker(&f.paths,ipc::geteuid(),|file| {calls.set(calls.get()+1);file.sync_all().unwrap();Ok(())}).unwrap();
        assert_eq!(calls.get(),2);assert_eq!(std::fs::read(marker(&f)).unwrap(),b"1\n");
    }
}
#[test]
fn marker_sync_failure_preserves_state_and_marker_for_conservative_retry() {
    for fail_at in [1,2] {
        let f=Fixture::new("");let _broker=f.broker();let before=durable(&f);let calls=Cell::new(0);
        assert!(publish_quiescence_marker(&f.paths,ipc::geteuid(),|_| {calls.set(calls.get()+1);
            if calls.get()==fail_at {Err(err!(EIO,"SYNTHETIC_SYNC_FAILURE"))}else{Ok(())}
        }).unwrap_err().is("SYNTHETIC_SYNC_FAILURE"));
        assert!(durable(&f)==before);assert_eq!(std::fs::read(marker(&f)).unwrap(),b"1\n");
        quiesce(&f.paths,ipc::geteuid()).unwrap();
    }
}
#[test]
fn marker_replacement_during_sync_is_detected_and_foreign_name_preserved() {
    let f=Fixture::new("");let _broker=f.broker();let changed=Cell::new(false);
    assert!(publish_quiescence_marker(&f.paths,ipc::geteuid(),|_| {
        if !changed.replace(true) {std::fs::remove_file(marker(&f)).unwrap();std::fs::write(marker(&f),b"x\n").unwrap();
            std::fs::set_permissions(marker(&f),std::fs::Permissions::from_mode(0o600)).unwrap();}Ok(())
    }).is_err());assert_eq!(std::fs::read(marker(&f)).unwrap(),b"x\n");
}
#[test]
fn actual_client_exchange_rejects_wrong_echo_rights_trailing_and_lost_reply() {
    for case in 0..5 {
        let (mut server,mut client)=UnixStream::pair().unwrap();
        let thread=std::thread::spawn(move|| {
            let until=Instant::now()+Duration::from_secs(2);
            let request:AdminRequest=decode_admin(&bounded_frame_before(&mut server,until).unwrap()).unwrap();
            ipc::recv_fd_packet(&server,0).unwrap();admin_eof(&mut server,until).unwrap();
            if case==4 {return;}
            let mut reply=AdminResponse {v:1,action:AdminAction::QuiesceIdle,binding:request.binding,challenge:request.challenge};
            if case==0 {reply.challenge[0]^=1;}if case==1 {reply.binding.pins_sha256="ef".repeat(32);}
            ipc::write_frame(&mut server,&ipc::to_cbor(&ipc::Reply::Ok(reply)).unwrap()).unwrap();
            if case==2 {let (unexpected_fd,_held_peer)=UnixStream::pair().unwrap();ipc::send_fd_packet(&server,&[unexpected_fd.as_raw_fd()]).unwrap();}
            else {ipc::send_fd_packet(&server,&[]).unwrap();}
            if case==3 {server.write_all(b"extra reply").unwrap();}
            let _=server.shutdown(Shutdown::Write);
        });
        assert!(admin_exchange(&mut client,&request(),Instant::now()+Duration::from_secs(2)).is_err());thread.join().unwrap();
    }
}
