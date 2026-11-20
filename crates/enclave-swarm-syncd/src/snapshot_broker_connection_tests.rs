// Exact new tests for the broker's real connection/descriptor boundary.
mod broker_connection_support { include!("snapshot_broker_connection_test_support.rs"); }
use broker_connection_support as bc;
use serde_json::{json, Value};
use std::{os::fd::IntoRawFd, sync::atomic::{AtomicUsize, Ordering}};

const BROKER_POSITIVE_CASES: &[&str] = &["readonly_publish","readonly_exact_returned_payload",
    "authorized_reopen","existing_prepare_no_descriptor","revoke_then_absent_revoke"];
const BROKER_TYPE_CASES: &[&str] = &["regular_rdwr","regular_wronly","directory","owned_fifo",
    "owned_pipe","owned_unix_socket","genuine_null_character_device","positive_after_refusals"];
const BROKER_RIGHTS_CASES: &[&str] = &["publish_zero_rights","duplicate_two_rights","distinct_two_rights",
    "seventeen_rights","reopen_unexpected_right","revoke_unexpected_right","prepare_unexpected_right",
    "wrong_marker_with_right","missing_marker_eof","positive_after_refusals"];
const BROKER_FRAME_CASES: &[&str] = &["declared_zero","declared_4097","declared_u32_max",
    "one_header_byte_eof","three_header_bytes_eof","short_body_eof","exact_4096_malformed_body",
    "header_absolute_deadline","body_absolute_deadline","positive_after_refusals"];
const BROKER_CBOR_CASES: &[&str] = &["trailing_cbor","unknown_field","unknown_operation",
    "declared_text_u64_max","declared_array_u64_max","declared_map_u64_max","uppercase_root",
    "short_root","traversal_root","canonical_unlisted_root","positive_after_refusals"];
const BROKER_LENGTH_CASES: &[&str] = &["signed_length_short_stage","signed_length_long_stage",
    "wrong_blake3","wrong_sha256","signed_exact_8gib_prepare_only","signed_8gib_plus_one",
    "signed_u64_max","tiny_valid_publish_after_refusals"];
const BROKER_AUTH_CASES: &[&str] = &["deny_empty_connection","deny_queued_hostile_frame_and_right",
    "deny_queued_valid_publish","accept_reaches_parser_refusal","accept_valid_publish_progress"];

#[test]
fn broker_connection_readonly_publish_reopen_prepare_revoke_progress() {
    bc::run_outer("snapshot_broker::tests::broker_connection_readonly_publish_reopen_prepare_revoke_progress",
        BROKER_POSITIVE_CASES,broker_positive_group);
}
#[test]
fn broker_connection_rejects_special_and_mutable_descriptors() {
    bc::run_outer("snapshot_broker::tests::broker_connection_rejects_special_and_mutable_descriptors",
        BROKER_TYPE_CASES,broker_type_group);
}
#[test]
fn broker_connection_exact_rights_marker_and_cleanup() {
    bc::run_outer("snapshot_broker::tests::broker_connection_exact_rights_marker_and_cleanup",
        BROKER_RIGHTS_CASES,broker_rights_group);
}
#[test]
fn broker_connection_frame_bounds_eof_and_deadlines() {
    bc::run_outer("snapshot_broker::tests::broker_connection_frame_bounds_eof_and_deadlines",
        BROKER_FRAME_CASES,broker_frame_group);
}
#[test]
fn broker_connection_strict_cbor_root_and_recovery() {
    bc::run_outer("snapshot_broker::tests::broker_connection_strict_cbor_root_and_recovery",
        BROKER_CBOR_CASES,broker_cbor_group);
}
#[test]
fn broker_connection_signed_length_digest_and_resource_bounds() {
    bc::run_outer("snapshot_broker::tests::broker_connection_signed_length_digest_and_resource_bounds",
        BROKER_LENGTH_CASES,broker_length_group);
}
#[test]
fn broker_connection_authentication_precedes_bytes_and_rights() {
    bc::run_outer("snapshot_broker::tests::broker_connection_authentication_precedes_bytes_and_rights",
        BROKER_AUTH_CASES,broker_auth_group);
}

fn broker_fresh_negative(book:&mut bc::Book,case:&'static str,
    check:impl FnOnce(&Fixture,&mut Broker)->Value) {
    book.run(case,|_| {
        let f=Fixture::new(""); let mut broker=f.broker();
        let refused=check(&f,&mut broker); bc::fresh_effects(&f,&broker);
        let recovery=bc::progress(&f,&mut broker);
        json!({"refused":refused,"no_new_publication_before_recovery":true,"recovery":recovery})
    });
}
fn broker_positive(book:&mut bc::Book,case:&'static str) {
    book.run(case,|_| {let f=Fixture::new(""); let mut broker=f.broker();bc::progress(&f,&mut broker)});
}
fn broker_positive_group(book:&mut bc::Book) {
    book.run("readonly_publish",|_| {
        let f=Fixture::new("");let mut broker=f.broker();let stage=f.stage(PAYLOAD);
        let before=bc::identity(&stage);
        let result=bc::exact_payload(bc::request(&mut broker,&Request::Publish{root:f.root_hash()},&[stage.as_raw_fd()]));
        assert_eq!(bc::identity(&stage),before);
        assert!(broker.state.records[&f.root_hash()].complete);
        assert!(broker.state.records[&f.root_hash()].owned_snapshot);
        json!({"published":result,"complete_owned_record":true,"sender_original_preserved":true})
    });
    book.run("readonly_exact_returned_payload",|_| {
        let f=Fixture::new("");let mut broker=f.broker();let stage=f.stage(PAYLOAD);
        let result=bc::exact_payload(bc::request(&mut broker,&Request::Publish{root:f.root_hash()},&[stage.as_raw_fd()]));
        let mut bytes=vec![0;PAYLOAD.len()];
        assert_eq!(std::os::unix::fs::FileExt::read_at(&stage,&mut bytes,0).unwrap(),PAYLOAD.len());
        assert_eq!(bytes,PAYLOAD);result
    });
    book.run("authorized_reopen",|_| {
        let f=Fixture::new("");let mut broker=f.broker();let stage=f.stage(PAYLOAD);
        let initial=bc::exact_payload(bc::request(&mut broker,&Request::Publish{root:f.root_hash()},&[stage.as_raw_fd()]));
        let reopened=bc::exact_payload(bc::request(&mut broker,&Request::Reopen{root:f.root_hash()},&[]));
        json!({"initial":initial,"reopened":reopened})
    });
    book.run("existing_prepare_no_descriptor",|_| {
        let f=Fixture::new("");let mut broker=f.broker();
        bc::no_descriptor(bc::request(&mut broker,&Request::Prepare{root:f.root_hash()},&[]));
        bc::fresh_effects(&f,&broker);
        let stage=f.stage(PAYLOAD);
        bc::exact_payload(bc::request(&mut broker,&Request::Publish{root:f.root_hash()},&[stage.as_raw_fd()]));
        let before=serde_json::to_value(&broker.state.records).unwrap();
        bc::no_descriptor(bc::request(&mut broker,&Request::Prepare{root:f.root_hash()},&[]));
        assert_eq!(serde_json::to_value(&broker.state.records).unwrap(),before);
        assert!(broker.state.stage_intent.is_none());
        json!({"existing_prepare":true,"new_request_operation":false,"no_descriptor":true,"records_unchanged":true})
    });
    book.run("revoke_then_absent_revoke",|_| {
        let f=Fixture::new("");let mut broker=f.broker();
        let other=f.root.join("unrelated-owner-file");std::fs::write(&other,b"preserve unrelated").unwrap();
        let recovery=bc::progress(&f,&mut broker);
        assert_eq!(std::fs::read(other).unwrap(),b"preserve unrelated");recovery
    });
}

fn broker_type_group(book:&mut bc::Book) {
    for &case in &BROKER_TYPE_CASES[..7] {
        broker_fresh_negative(book,case,move |f,broker| {
            let path=f.root.join("descriptor-input");
            let (file,held):(File,Vec<File>)=match case {
                "regular_rdwr"|"regular_wronly"=>{
                    std::fs::write(&path,PAYLOAD).unwrap();
                    (File::options().read(case=="regular_rdwr").write(true).open(&path).unwrap(),vec![])
                }
                "directory"=>(File::open(&f.root).unwrap(),vec![]),
                "owned_fifo"=>{
                    use std::os::unix::ffi::OsStrExt;
                    let name=std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe{libc::mkfifo(name.as_ptr(),0o600)},0);
                    let reader=File::options().read(true).custom_flags(libc::O_NONBLOCK|libc::O_CLOEXEC).open(&path).unwrap();
                    let writer=File::options().write(true).custom_flags(libc::O_NONBLOCK|libc::O_CLOEXEC).open(&path).unwrap();
                    (reader,vec![writer])
                }
                "owned_pipe"=>{
                    let mut descriptors=[-1;2];assert_eq!(unsafe{libc::pipe(descriptors.as_mut_ptr())},0);
                    let reader=unsafe{File::from_raw_fd(descriptors[0])};
                    let writer=unsafe{File::from_raw_fd(descriptors[1])};
                    let flags=bc::flags(&reader);
                    assert_eq!(unsafe{libc::fcntl(reader.as_raw_fd(),libc::F_SETFL,flags|libc::O_NONBLOCK)},0);
                    (reader,vec![writer])
                }
                "owned_unix_socket"=>{
                    let (a,b)=UnixStream::pair().unwrap();
                    (unsafe{File::from_raw_fd(a.into_raw_fd())},vec![unsafe{File::from_raw_fd(b.into_raw_fd())}])
                }
                "genuine_null_character_device"=>{
                    #[cfg(target_os="linux")]
                    let file=if std::env::var_os("depot_PHASE1_NULL_STDIN").as_deref()==Some(std::ffi::OsStr::new("1")) {
                        let fd=unsafe{libc::fcntl(libc::STDIN_FILENO,libc::F_DUPFD_CLOEXEC,3)};
                        assert!(fd>=0);unsafe{File::from_raw_fd(fd)}
                    } else {File::open("/dev/null").unwrap()};
                    #[cfg(not(target_os="linux"))]
                    let file=File::open("/dev/null").unwrap();
                    use std::os::unix::fs::FileTypeExt;
                    assert!(file.metadata().unwrap().file_type().is_char_device());
                    assert_eq!(bc::flags(&file)&libc::O_ACCMODE,libc::O_RDONLY);
                    (file,vec![])
                }
                _=>panic!("unknown descriptor case"),
            };
            use std::os::unix::fs::FileTypeExt;
            let m=file.metadata().unwrap();
            match case {
                "regular_rdwr"=>{assert!(m.is_file());assert_eq!(bc::flags(&file)&libc::O_ACCMODE,libc::O_RDWR);}
                "regular_wronly"=>{assert!(m.is_file());assert_eq!(bc::flags(&file)&libc::O_ACCMODE,libc::O_WRONLY);}
                "directory"=>assert!(m.is_dir()),
                "owned_fifo"|"owned_pipe"=>{assert!(m.file_type().is_fifo());assert_ne!(bc::flags(&file)&libc::O_NONBLOCK,0);assert_eq!(held.len(),1);}
                "owned_unix_socket"=>assert!(m.file_type().is_socket()),
                _=>(),
            }
            let before=bc::identity(&file);
            let refused=bc::reply_refusal(bc::request(broker,&Request::Publish{root:f.root_hash()},&[file.as_raw_fd()]),"BROKER_STAGE");
            assert_eq!(bc::identity(&file),before);
            drop(held);json!({"descriptor":before,"refusal":refused,"original_preserved":true})
        });
    }
    broker_positive(book,"positive_after_refusals");
}
fn broker_rights_group(book:&mut bc::Book) {
    for &case in &BROKER_RIGHTS_CASES[..9] {
        broker_fresh_negative(book,case,move |f,broker| {
            let first=f.stage(PAYLOAD);let second=f.stage(PAYLOAD);
            let before=[bc::identity(&first),bc::identity(&second)];
            let mut request=Request::Publish{root:f.root_hash()};
            if case=="reopen_unexpected_right" {request=Request::Reopen{root:f.root_hash()};}
            if case=="revoke_unexpected_right" {request=Request::Revoke{root:f.root_hash()};}
            if case=="prepare_unexpected_right" {request=Request::Prepare{root:f.root_hash()};}
            let frame=bc::frame(&ipc::to_cbor(&request).unwrap());
            let many=vec![first.as_raw_fd();17];
            let rights=match case {
                "publish_zero_rights"=>vec![],"duplicate_two_rights"=>vec![first.as_raw_fd();2],
                "distinct_two_rights"=>vec![first.as_raw_fd(),second.as_raw_fd()],
                "seventeen_rights"=>many,_=>vec![first.as_raw_fd()],
            };
            let packet=match case {
                "seventeen_rights"=>bc::Packet::Raw(0x46,&rights),
                "wrong_marker_with_right"=>bc::Packet::Raw(0x47,&rights),
                "missing_marker_eof"=>bc::Packet::Missing,_=>bc::Packet::Normal(&rights),
            };
            let outcome=bc::wire(broker,&frame,packet,case=="missing_marker_eof");
            let observed=if matches!(case,"publish_zero_rights"|"reopen_unexpected_right"|"revoke_unexpected_right"|"prepare_unexpected_right") {
                // connection enforces the decoded operation's exact count
                // before execute/lifecycle/typed-reply handling.
                bc::connection_refusal(outcome,"BROKER_FD_COUNT")
            } else {bc::connection_refusal(outcome,"SCM_RIGHTS_TRUNCATED_OR_INVALID")};
            assert_eq!([bc::identity(&first),bc::identity(&second)],before);
            for file in [&first,&second] {
                let mut bytes=vec![0;PAYLOAD.len()];
                assert_eq!(std::os::unix::fs::FileExt::read_at(file,&mut bytes,0).unwrap(),PAYLOAD.len());assert_eq!(bytes,PAYLOAD);
            }
            json!({"refusal":observed,"sent_rights":rights.len(),"sender_originals_preserved":before})
        });
    }
    broker_positive(book,"positive_after_refusals");
}

fn broker_deadline(f:&Fixture,broker:&mut Broker,body:bool)->Value {
    let (server,mut client)=bc::pair();
    // This duplicate only observes the same receive queue; it never reads or
    // changes status flags. Its lifetime ends in the joined writer below.
    let observer=server.try_clone().unwrap();
    let (entered_tx,entered_rx)=std::sync::mpsc::channel();
    let writer=std::thread::spawn(move || {
        let start:Instant=entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let packets:Vec<Vec<u8>>=if body {vec![vec![0,0,0,4,0xff],vec![0xff],vec![0xff],vec![0xff]]}
            else {vec![vec![0],vec![0],vec![0],vec![1,0xff]]};
        let mut events=vec![];
        for (index,(at,bytes)) in [0u64,1500,3000,6500].into_iter().zip(packets).enumerate() {
            let target=start+Duration::from_millis(at);
            std::thread::sleep(target.saturating_duration_since(Instant::now()));
            let attempted=start.elapsed().as_millis() as u64;
            let result=client.write_all(&bytes);
            let write_ok=result.is_ok();
            let mut drained_ms=None;let mut queued_after=None;
            if index<3 {
                assert!(write_ok,"all initial progress drips must actually enqueue");
                assert!(attempted<4500,"initial drip missed original frame budget");
                let until=(Instant::now()+Duration::from_millis(500)).min(start+Duration::from_millis(4500));
                loop {
                    let mut available:libc::c_int=-1;
                    assert_eq!(unsafe{libc::ioctl(observer.as_raw_fd(),libc::FIONREAD,&mut available)},0);
                    assert!(available>=0);
                    if available==0 {
                        let observed=Instant::now();
                        // Check the precise deadline before accepting queue0;
                        // a descheduled observer must not claim a500ms sample.
                        assert!(observed<=until,"queue drain was observed after its bounded observation window");
                        queued_after=Some(available);
                        drained_ms=Some(observed.duration_since(start).as_millis() as u64);break;
                    }
                    assert!(Instant::now()<until,"actual broker did not consume progress drip before original deadline");
                    std::thread::sleep(Duration::from_millis(2));
                }
                assert!(drained_ms.unwrap()<5000);
            }
            events.push(json!({"scheduled_ms":at,"attempted_ms":attempted,
                "bytes":bytes,"write_ok":write_ok,"error_kind":result.err().map(|e|format!("{:?}",e.kind())),
                "FIONREAD_after":queued_after,"receive_queue_drained_ms":drained_ms}));
        }
        drop(observer);
        (client,events)
    });
    let mut auth_started=None;
    let result=connection(server,broker,|_|{
        let at=Instant::now();auth_started=Some(at);entered_tx.send(at).unwrap();Ok(())
    });
    let returned_ms=auth_started.unwrap().elapsed().as_millis() as u64;
    let (client,events)=writer.join().unwrap();
    let outcome=bc::finish(result,client);
    let bc::Outcome::Connection(reason)=outcome else {panic!("expected absolute frame deadline refusal")};
    assert!(reason=="BROKER_FRAME"||reason=="BROKER_FRAME_DEADLINE");
    for event in &events[..3] {
        assert_eq!(event["write_ok"],true);
        assert!(event["attempted_ms"].as_u64().unwrap()<4500);
        assert_eq!(event["FIONREAD_after"],0);
        assert!(event["receive_queue_drained_ms"].as_u64().unwrap()<5000);
    }
    let final_attempt=events.last().unwrap()["attempted_ms"].as_u64().unwrap();
    assert!(returned_ms>=4000 && returned_ms<final_attempt,
        "actual refusal must precede final completing bytes; observed {returned_ms}/{final_attempt}");
    bc::fresh_effects(f,broker);
    json!({"error":reason,"returned_ms":returned_ms,"writer_events":events,
        "receive_progress":"first three real writes consumed, nonconsuming FIONREAD=0 before original5s budget",
        "observer_dropped_before_cleanup":true,
        "clock_scope":"finite observed schedule; no hard scheduler or syscall bound"})
}

fn broker_frame_group(book:&mut bc::Book) {
    for &case in &BROKER_FRAME_CASES[..7] {
        broker_fresh_negative(book,case,move |_,broker| {
            let bytes=match case {
                "declared_zero"=>0u32.to_be_bytes().to_vec(),
                "declared_4097"=>4097u32.to_be_bytes().to_vec(),
                "declared_u32_max"=>u32::MAX.to_be_bytes().to_vec(),
                "one_header_byte_eof"=>vec![0],"three_header_bytes_eof"=>vec![0,0,0],
                "short_body_eof"=>vec![0,0,0,10,0xa1,0x67],
                "exact_4096_malformed_body"=>bc::frame(&vec![0xff;4096]),_=>unreachable!(),
            };
            let eof=matches!(case,"one_header_byte_eof"|"three_header_bytes_eof"|"short_body_eof");
            let reason=if case=="exact_4096_malformed_body" {"BROKER_REQUEST"} else {"BROKER_FRAME"};
            let result=bc::connection_refusal(bc::wire(broker,&bytes,bc::Packet::Missing,eof),reason);
            json!({"wire_bytes":bytes.len(),"write_shutdown":eof,"refusal":result})
        });
    }
    broker_fresh_negative(book,"header_absolute_deadline",|f,b|broker_deadline(f,b,false));
    broker_fresh_negative(book,"body_absolute_deadline",|f,b|broker_deadline(f,b,true));
    broker_positive(book,"positive_after_refusals");
}

fn broker_hostile_body(case:&str)->Vec<u8> {
    let marker=match case {"declared_text_u64_max"=>0x7b,"declared_array_u64_max"=>0x9b,
        "declared_map_u64_max"=>0xbb,_=>panic!("unknown bounded parser case")};
    // CBOR {"Prepare":{"root":<text/array/map declared u64::MAX>}}.
    // The declared value has no body. Actual input is24 bytes, never a huge buffer.
    let mut bytes=vec![0xa1,0x67];bytes.extend_from_slice(b"Prepare");
    bytes.extend_from_slice(&[0xa1,0x64]);bytes.extend_from_slice(b"root");
    bytes.push(marker);bytes.extend_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(bytes.len(),24);bytes
}
fn broker_parser_case(case:&str)->Value {
    assert!(["declared_text_u64_max","declared_array_u64_max","declared_map_u64_max"].contains(&case));
    let f=Fixture::new("");let mut broker=f.broker();let bytes=broker_hostile_body(case);
    let refusal=bc::connection_refusal(bc::wire(&mut broker,&bc::frame(&bytes),bc::Packet::Normal(&[]),false),"BROKER_REQUEST");
    bc::fresh_effects(&f,&broker);let recovery=bc::progress(&f,&mut broker);
    json!({"body_hex":hex::encode(&bytes),"body_bytes":bytes.len(),"refusal":refusal,"recovery":recovery,
        "safety_scope":"pinned typed parser bounded actual input + short child watchdog; no allocator-cap or Darwin RLIMIT_AS claim"})
}
fn broker_cbor_group(book:&mut bc::Book) {
    for &case in &BROKER_CBOR_CASES[..3] {
        broker_fresh_negative(book,case,move |f,broker| {
            let bytes=match case {
                "trailing_cbor"=>{let mut bytes=ipc::to_cbor(&Request::Prepare{root:f.root_hash()}).unwrap();bytes.push(0);bytes},
                "unknown_field"=>ipc::to_cbor(&json!({"Prepare":{"root":f.root_hash(),"path":"/forbidden"}})).unwrap(),
                "unknown_operation"=>ipc::to_cbor(&json!({"Arbitrary":{"root":f.root_hash()}})).unwrap(),_=>unreachable!(),
            };
            let reason=if case=="trailing_cbor" {"BROKER_REQUEST_TRAILING"} else {"BROKER_REQUEST"};
            bc::connection_refusal(bc::wire(broker,&bc::frame(&bytes),bc::Packet::Normal(&[]),false),reason)
        });
    }
    for &case in &BROKER_CBOR_CASES[3..6] {book.run(case,|book|book.parser(case));}
    for &case in &BROKER_CBOR_CASES[6..10] {
        broker_fresh_negative(book,case,move |f,broker| {
            let root=match case {"uppercase_root"=>"AB".repeat(32),"short_root"=>"a".repeat(63),
                "traversal_root"=>"../escape".to_owned(),"canonical_unlisted_root"=>"0".repeat(64),_=>unreachable!()};
            assert_ne!(root,f.root_hash());
            let reason=if case=="canonical_unlisted_root" {"BROKER_TARGET"} else {"BROKER_ROOT"};
            bc::reply_refusal(bc::request(broker,&Request::Prepare{root},&[]),reason)
        });
    }
    broker_positive(book,"positive_after_refusals");
}

fn broker_restore_metadata(f:&mut Fixture,broker:&mut Broker,original:BTreeMap<String,TargetFile>)->Value {
    // refresh deliberately persisted verified version2 before later refusal.
    // Preserve that floor and demonstrate actual rollback refusal, then restore
    // through independently signed newer metadata rather than erasing state.
    f.targets=original;
    f.metadata(1,&f.targets,EXP);
    let rollback=bc::reply_refusal(bc::request(broker,&Request::Prepare{root:f.root_hash()},&[]),"TUF_ROLLBACK");
    f.metadata(3,&f.targets,EXP);
    let progress=bc::progress(f,broker);
    json!({"lower_revision_refused":rollback,"higher_signed_revision_recovery":progress})
}
fn broker_length_group(book:&mut bc::Book) {
    for &case in &BROKER_LENGTH_CASES[..2] {
        broker_fresh_negative(book,case,move |f,broker| {
            let bytes=if case=="signed_length_short_stage" {PAYLOAD[..PAYLOAD.len()-1].to_vec()}
                else {let mut b=PAYLOAD.to_vec();b.push(0);b};
            let stage=f.stage(&bytes);let before=bc::identity(&stage);
            let result=bc::reply_refusal(bc::request(broker,&Request::Publish{root:f.root_hash()},&[stage.as_raw_fd()]),"BROKER_STAGE_LENGTH");
            assert_eq!(bc::identity(&stage),before);
            json!({"signed_length":PAYLOAD.len(),"actual_stage":before,"refusal":result})
        });
    }
    for &case in &BROKER_LENGTH_CASES[2..4] {
        book.run(case,move |_| {
            let mut f=Fixture::new("");let original=f.targets.clone();
            let name=if case=="wrong_blake3" {"blake3"} else {"sha256"};
            let current=&f.targets["model.bin"].hashes[name];
            let wrong=format!("{}{}",if current.starts_with('0') {'1'} else {'0'},&current[1..]);
            f.targets.get_mut("model.bin").unwrap().hashes.insert(name.to_owned(),wrong);
            f.metadata(2,&f.targets,EXP);let mut broker=f.broker();let stage=f.stage(PAYLOAD);
            let result=bc::reply_refusal(bc::request(&mut broker,&Request::Publish{root:f.root_hash()},&[stage.as_raw_fd()]),"SEALED_DIGEST");
            assert!(broker.state.records.is_empty());assert!(broker.state.stage_intent.is_some());
            let calls=f.platform.calls.lock().unwrap().clone();assert!(calls.contains(&"capacity"));
            assert!(!calls.iter().any(|c|matches!(*c,"clone"|"snapshot"|"mount"|"holders")));
            let stages=f.config.source_mount.join(".broker-stages");
            assert!(stages.is_dir());assert_eq!(std::fs::read_dir(stages).unwrap().count(),0);
            let recovery=broker_restore_metadata(&mut f,&mut broker,original);
            json!({"hash_predicate":name,"refusal":result,"platform_calls_before_recovery":calls,
                "private_copy_hash_check_reached":true,"retained_intent_before_recovery":true,"recovery":recovery})
        });
    }
    for &case in &BROKER_LENGTH_CASES[4..7] {
        book.run(case,move |_| {
            let mut f=Fixture::new("");let original=f.targets.clone();
            let length=match case {"signed_exact_8gib_prepare_only"=>crate::streaming::MAX_ARTIFACT_BYTES,
                "signed_8gib_plus_one"=>crate::streaming::MAX_ARTIFACT_BYTES+1,"signed_u64_max"=>u64::MAX,_=>unreachable!()};
            f.targets.get_mut("model.bin").unwrap().length=length;f.metadata(2,&f.targets,EXP);
            let mut broker=f.broker();
            let outcome=bc::request(&mut broker,&Request::Prepare{root:f.root_hash()},&[]);
            let result=if case=="signed_exact_8gib_prepare_only" {bc::no_descriptor(outcome);json!({"prepare_metadata_accepted":true})}
                else {bc::reply_refusal(outcome,"ADMISSION_TOO_LARGE")};
            bc::fresh_effects(&f,&broker);
            let recovery=broker_restore_metadata(&mut f,&mut broker,original);
            json!({"signed_length":length,"actual_payload_materialized_bytes":0,"prepare_only":true,
                "result":result,"recovery":recovery,"positive_8gib_publication":false})
        });
    }
    broker_positive(book,"tiny_valid_publish_after_refusals");
}

fn broker_auth_group(book:&mut bc::Book) {
    for &case in &BROKER_AUTH_CASES[..3] {
        broker_fresh_negative(book,case,move |f,broker| {
            let (server,mut client)=bc::pair();let peek=server.try_clone().unwrap();
            let stage=f.stage(PAYLOAD);let original=bc::identity(&stage);
            let bytes=match case {
                "deny_empty_connection"=>vec![],
                "deny_queued_hostile_frame_and_right"=>u32::MAX.to_be_bytes().to_vec(),
                "deny_queued_valid_publish"=>bc::frame(&ipc::to_cbor(&Request::Publish{root:f.root_hash()}).unwrap()),
                _=>unreachable!(),
            };
            if !bytes.is_empty() {client.write_all(&bytes).unwrap();ipc::send_fd_packet(&client,&[stage.as_raw_fd()]).unwrap();}
            let calls=AtomicUsize::new(0);let began=Instant::now();
            let result=connection(server,broker,|_|{calls.fetch_add(1,Ordering::SeqCst);Err(err!(EACCES,"FIXTURE_DENY"))});
            assert_eq!(calls.load(Ordering::SeqCst),1);
            assert!(result.as_ref().unwrap_err().is("FIXTURE_DENY"));
            let peeked=if bytes.is_empty() {
                let mut byte=[0u8];let n=unsafe{libc::recv(peek.as_raw_fd(),byte.as_mut_ptr().cast(),1,libc::MSG_PEEK|libc::MSG_DONTWAIT)};
                assert_eq!(n,-1);assert_eq!(std::io::Error::last_os_error().kind(),std::io::ErrorKind::WouldBlock);vec![]
            } else {
                let mut header=[0u8;4];let n=unsafe{libc::recv(peek.as_raw_fd(),header.as_mut_ptr().cast(),4,libc::MSG_PEEK|libc::MSG_DONTWAIT)};
                assert_eq!(n,4);assert_eq!(&header,&bytes[..4]);header.to_vec()
            };
            drop(peek);
            let refused=bc::connection_refusal(bc::finish(result,client),"FIXTURE_DENY");
            assert_eq!(bc::identity(&stage),original);
            json!({"refusal":refused,"authenticator_calls":1,"queued_prefix_preserved":hex::encode(peeked),
                "elapsed_ms":began.elapsed().as_millis() as u64,"sender_original_preserved":true,
                "fixture_authenticator":true,"production_identity_accepted":false})
        });
    }
    broker_fresh_negative(book,"accept_reaches_parser_refusal",|_,broker| {
        bc::connection_refusal(bc::wire(broker,&bc::frame(&[0xff]),bc::Packet::Missing,false),"BROKER_REQUEST")
    });
    broker_positive(book,"accept_valid_publish_progress");
}
