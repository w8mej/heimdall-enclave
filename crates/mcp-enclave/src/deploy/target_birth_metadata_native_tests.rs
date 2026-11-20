//! SOFTWARE mechanics used by the native composition; no actual native birth,
//! guard, accounts, SOFTWARE approval or inhibited EX capability is fabricated.
//! These tests reuse real readonly fixture FDs and actual metadata syscalls.
use super::*;

#[test]
fn original_closed_payload_and_runtime_scopes_are_disjoint_and_duplicate_scope_refuses_before_effects() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut f=Fixture::new();f.controls();
    let payload=OwnMetadataPlan::build(&f.state,Scope::Payload).unwrap();
    let runtime=OwnMetadataPlan::build(&f.state,Scope::Runtime).unwrap();
    let mut paths=payload.declarations.keys().chain(runtime.declarations.keys()).cloned().collect::<Vec<_>>();
    paths.sort_by_key(|path|(path.components().count(),path.clone()));paths.dedup();
    for path in paths {let relative=path.strip_prefix(&f.state.plan.root).unwrap().to_str().unwrap().to_owned();f.directory(&relative);}
    // Empty fixture denial observations do NOT call prepare_actual and cannot
    // authorize the native constructor, which requires actual approval+EX.
    let first=OwnMetadataAttempt::prepare(&f.state,Scope::Payload,RetainedDirectoryExclusions {identities:BTreeSet::new()}).unwrap();
    let second=OwnMetadataAttempt::prepare(&f.state,Scope::Runtime,RetainedDirectoryExclusions {identities:BTreeSet::new()}).unwrap();
    first.assert_disjoint(&second).unwrap();
    let duplicate=OwnMetadataAttempt::prepare(&f.state,Scope::Payload,RetainedDirectoryExclusions {identities:BTreeSet::new()}).unwrap();
    assert!(first.assert_disjoint(&duplicate).unwrap_err().is("BIRTH_METADATA_SCOPE_ALIAS"));
    for attempt in [&first,&second,&duplicate] {
        assert!(attempt.kernel.history.iter().all(|node|node.calls.is_empty()&&node.syncs.is_empty()));
        assert!(attempt.observations(&f.state).is_empty());
        assert!(attempt.retained_completed_observations(&f.state).iter().any(|error|error.is("BIRTH_METADATA_NOT_COMPLETE")));
    }
    hidden_root(&f.state).unwrap();flags_false(&f.state);
}

#[test]
fn completion_flag_without_actual_syscall_and_durability_history_never_supplies_completed_metadata() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);let mut f=Fixture::new();
    let mut a=f.kernel("payload/leaf",0o755);
    assert!(a.completed_history().unwrap_err().is("BIRTH_METADATA_NOT_COMPLETE"));
    // An internal software-only corrupted completion flag is not a native
    // capability or event. The denial checker requires actual retained calls,
    // exact predicted changes and both sync results as well.
    a.complete=true;assert!(a.completed_history().unwrap_err().is("BIRTH_METADATA_COMPLETION_HISTORY"));
    a.complete=false;a.apply(&mut f.state,None,&mut||Vec::new(),&mut sync).unwrap();a.completed_history().unwrap();
    let old=a.history[0].calls[0].expected_committed;a.history[0].calls[0].expected_committed=false;
    assert!(a.completed_history().unwrap_err().is("BIRTH_METADATA_COMPLETION_HISTORY"));a.history[0].calls[0].expected_committed=old;
    a.history[0].syncs[1].error=Some(err!(EIO,"METADATA_CORRUPTED_SYNC_HISTORY"));
    assert!(a.completed_history().unwrap_err().is("BIRTH_METADATA_COMPLETION_HISTORY"));
    a.history[0].syncs[1].error=None;a.completed_history().unwrap();
    a.poisoned=true;assert!(a.completed_history().unwrap_err().is("BIRTH_METADATA_NOT_COMPLETE"));
    hidden_root(&f.state).unwrap();flags_false(&f.state);
}

#[test]
fn later_actual_guard_refusal_retains_first_directory_effect_and_never_touches_the_second_original() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);let mut f=Fixture::new();
    let first=f.kernel("payload/first",0o755);let second=f.kernel("payload/second",0o755);
    let first_path=first.steps[0].origin.path.clone();let second_path=second.steps[0].origin.path.clone();
    let first_fd=first.steps[0].origin.fd;let second_fd=second.steps[0].origin.fd;
    let mut a=KernelMetadataAttempt::new(first.steps.into_iter().chain(second.steps).collect(),first.denied);
    let error=a.apply(&mut f.state,None,&mut|| {
        if std::fs::metadata(&first_path).unwrap().mode()&0o7777==0o755 {
            vec![err!(EACCES,"METADATA_MULTINODE_GUARD_LOST")]
        }else{Vec::new()}
    },&mut sync).unwrap_err();
    assert!(error.is("METADATA_MULTINODE_GUARD_LOST"));
    assert_eq!(a.history[0].calls.len(),1);assert!(a.history[0].calls[0].expected_committed);
    assert!(a.history[1].calls.is_empty()&&a.history[1].syncs.is_empty());
    assert_eq!(std::fs::metadata(&first_path).unwrap().mode()&0o7777,0o755);
    assert_eq!(std::fs::metadata(&second_path).unwrap().mode()&0o7777,0o700);
    assert_eq!(f.state.dirs[&first_path].file.as_raw_fd(),first_fd);assert_eq!(f.state.dirs[&second_path].file.as_raw_fd(),second_fd);
    assert!(f.state.dirs[&first_path].private&&f.state.dirs[&second_path].private&&a.poisoned&&f.state.poisoned);
    let failure=a.failure.as_ref().unwrap();assert!(failure.error.is("METADATA_MULTINODE_GUARD_LOST"));
    assert!(failure.boundary_errors.iter().any(|error|error.is("METADATA_MULTINODE_GUARD_LOST")));
    assert!(failure.final_errors.iter().any(|error|error.is("METADATA_MULTINODE_GUARD_LOST")));
    hidden_root(&f.state).unwrap();flags_false(&f.state);
}

#[test]
fn second_directory_sync_refusal_keeps_both_verified_effects_and_every_original_ledger() {
    let _serial=SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);let mut f=Fixture::new();
    let first=f.kernel("payload/first",0o755);let second=f.kernel("payload/second",0o755);
    let first_path=first.steps[0].origin.path.clone();let second_path=second.steps[0].origin.path.clone();
    let mut a=KernelMetadataAttempt::new(first.steps.into_iter().chain(second.steps).collect(),first.denied);
    let calls=Cell::new(0);let error=a.apply(&mut f.state,None,&mut||Vec::new(),&mut|file| {
        let call=calls.get();calls.set(call+1);
        if call==2 {Err(err!(EIO,"METADATA_SECOND_DIRECTORY_SYNC_FAIL"))}else{sync(file)}
    }).unwrap_err();
    assert!(error.is("METADATA_SECOND_DIRECTORY_SYNC_FAIL"));assert_eq!(calls.get(),3);
    for (index,path) in [&first_path,&second_path].into_iter().enumerate() {
        assert_eq!(a.history[index].calls.len(),1);assert!(a.history[index].calls[0].expected_committed);
        assert_eq!(a.steps[index].origin.stamp.mode&0o7777,0o700);
        assert_eq!(f.state.dirs[path].stamp.mode&0o7777,0o755);assert!(f.state.dirs[path].private);
        assert_eq!(f.state.dirs[path].file.as_raw_fd(),a.steps[index].origin.fd);
    }
    assert_eq!(a.history[0].syncs.len(),2);assert_eq!(a.history[1].syncs.len(),1);
    assert!(a.history[1].syncs[0].error.as_ref().unwrap().is("METADATA_SECOND_DIRECTORY_SYNC_FAIL"));
    assert!(a.failure.as_ref().unwrap().error.is("METADATA_SECOND_DIRECTORY_SYNC_FAIL"));
    let original_history=a.history.iter().map(|node|(node.calls.len(),node.syncs.len())).collect::<Vec<_>>();
    assert!(a.apply(&mut f.state,None,&mut||Vec::new(),&mut sync).unwrap_err().is("BIRTH_METADATA_OWNER_POISONED"));
    assert_eq!(a.history.iter().map(|node|(node.calls.len(),node.syncs.len())).collect::<Vec<_>>(),original_history);
    assert!(a.failure.as_ref().unwrap().error.is("METADATA_SECOND_DIRECTORY_SYNC_FAIL"));hidden_root(&f.state).unwrap();flags_false(&f.state);
}
