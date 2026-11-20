//! Shared policy and native auxiliary observation adapters.

pub use enclave_core::memory_budget::*;

#[cfg(test)]
mod tests {
    use super::*;
    use enclave_core::{daemon::DaemonId,ipc::DaemonStatus};
    const MIB:u64=1024*1024;
    use enclave_core::resource::FootprintSource;

    fn statuses() -> [DaemonStatus; 5] {
        DaemonId::ALL.map(|d| DaemonStatus {
            daemon_uid: d.uid(),
            binary: d.binary().into(),
            pid: 123,
            rss_bytes: 1,
            rss_ceiling_bytes: u64::MAX,
            boot_epoch_id: String::new(),
            rpc_seq_u64: 0,
            state: "profile=L2".into(),
            phys_footprint_bytes: d.rss_ceiling_bytes(),
            phys_footprint_source: FootprintSource::DarwinTaskVmInfo,
        })
    }
    fn check(s: &[DaemonStatus; 5]) -> MemoryBudget {
        evaluate(std::array::from_fn(|i| Some(&s[i])))
    }

    #[test]
    fn exact_caps_and_one_byte_breaches_use_footprint_not_rss() {
        let mut s = statuses();
        let b = check(&s);
        assert!(b.compliant);
        assert_eq!(b.total_bytes, Some(200 * MIB));
        assert_eq!(b.other_bytes, Some(152 * MIB));
        for i in 0..5 {
            s = statuses();
            s[i].phys_footprint_bytes += 1;
            assert!(!check(&s).compliant);
            assert!(!check(&s).daemons[i].within_ceiling);
        }
        s = statuses();
        s[0].phys_footprint_bytes = 1;
        s[2].phys_footprint_bytes += 1;
        let b = check(&s);
        assert!(b.total_bytes.unwrap() < 200 * MIB);
        assert!(!b.compliant);
    }

    #[test]
    fn missing_zero_legacy_wrong_identity_and_overflow_fail_closed() {
        for i in 0..5 {
            let mut s = statuses();
            s[i].phys_footprint_bytes = 0;
            assert!(check(&s).unknown_required);
            s = statuses();
            s[i].phys_footprint_source = FootprintSource::Unknown;
            assert!(check(&s).unknown_required);
            s = statuses();
            s[i].daemon_uid = 0;
            assert!(check(&s).unknown_required);
            let s = statuses();
            let mut input = std::array::from_fn(|n| Some(&s[n]));
            input[i] = None;
            assert!(!evaluate(input).compliant);
        }
        let mut s = statuses();
        s[0].phys_footprint_bytes = u64::MAX;
        let b = check(&s);
        assert!(b.overflow);
        assert!(!b.compliant);
        assert_eq!(b.total_bytes, None);
        // Missing data must not hide an independent overflow in known samples.
        s = statuses();
        s[0].phys_footprint_source = FootprintSource::Unknown;
        s[1].phys_footprint_bytes = u64::MAX;
        let b = check(&s);
        assert!(b.unknown_required && b.overflow && !b.compliant);
        assert_eq!(b.total_bytes, None);
        assert_eq!(b.other_bytes, None);
        let mut wire = serde_json::to_value(&statuses()[0]).unwrap();
        wire.as_object_mut()
            .unwrap()
            .remove("phys_footprint_source");
        assert_eq!(
            serde_json::from_value::<DaemonStatus>(wire)
                .unwrap()
                .phys_footprint_source,
            FootprintSource::Unknown
        );
    }
    #[test]
    fn production_health_and_measure_adapters_agree_and_preserve_profile_gate() {
        for mode in 0..5 {
            let mut s = statuses();
            for v in &mut s {
                v.rss_bytes = u64::MAX;
            }
            match mode {
                1 => s[1].phys_footprint_bytes += 1,
                2 => s[1].phys_footprint_source = FootprintSource::Unknown,
                3 => s[1].phys_footprint_bytes = u64::MAX,
                4 => s[1].phys_footprint_bytes = 0,
                _ => {}
            }
            let (memory, healthy) = crate::deploy::health::authenticated_health(
                "L2",
                std::array::from_fn(|i| Some(&s[i])),
            );
            let report = crate::ctl::measure_observations(
                s.clone().map(Some),
                "fixture".into(),
                "fixture".into(),
                4096,
            );
            assert_eq!(report.budget.compliant, mode == 0);
            assert_eq!(memory.compliant, report.budget.compliant);
            assert_eq!(healthy, report.budget.compliant);
            assert_eq!(memory.total_bytes, report.physical_memory.total_bytes);
        }
        let mut s = statuses();
        s[0].state = "profile=L1".into();
        let (memory, healthy) =
            crate::deploy::health::authenticated_health("L2", std::array::from_fn(|i| Some(&s[i])));
        assert!(memory.compliant);
        assert!(!healthy);
        assert!(
            !crate::deploy::health::authenticated_health(
                "invalid",
                std::array::from_fn(|i| Some(&s[i]))
            )
            .1
        );
    }
    #[test]
    fn auxiliary_health_and_measure_use_same_exact_policy() {
        let s=statuses();
        for bytes in [32*MIB,32*MIB+1] {
            let auxiliary=AuxiliaryObservations{intent:AuxiliaryObservation::Sample{uid:501,expected_uid:501,pid:123,bytes,source:FootprintSource::DarwinProcPidRusage},browser:AuxiliaryObservation::Inactive};
            let (memory,healthy)=crate::deploy::health::authenticated_health_with_auxiliary("L2",std::array::from_fn(|i|Some(&s[i])),&auxiliary);
            let report=crate::ctl::measure_with_auxiliary(s.clone().map(Some),auxiliary,"fixture".into(),"fixture".into(),4096);
            assert_eq!(healthy,bytes==32*MIB);assert_eq!(memory.compliant,report.budget.compliant);
            assert_eq!(memory.active_prompt_bytes,report.physical_memory.active_prompt_bytes);
        }
        let auxiliary=AuxiliaryObservations{intent:AuxiliaryObservation::Unknown,browser:AuxiliaryObservation::Inactive};
        let report=crate::ctl::measure_with_auxiliary(s.map(Some),auxiliary,"fixture".into(),"fixture".into(),4096);
        assert!(report.physical_memory.unknown_required&&!report.budget.compliant);
    }
    #[test]
    fn auxiliary_launchctl_requires_unambiguous_presence_or_explicit_inactive() {
        assert_eq!(launched_pid("state = running\npid = 123\n"),Some(Some(123)));
        for state in ["not running","waiting","exited"] {assert_eq!(launched_pid(&format!("state = {state}\n")),Some(None));}
        for text in ["", "state = running", "pid = 0", "pid = 1", "pid = invalid", "pid = 123\npid = 124", "pid = 123\npid = 123"] {assert_eq!(launched_pid(text),None);}
    }

}

/// Observe only configured auxiliary roles. A known inactive selected role is
/// zero; a failed/unauthenticated probe stays Unknown. No request is sent to a
/// GUI helper, and no prompt or browser operation is started.
pub fn observe_auxiliary(env:&crate::ctl::Env)->AuxiliaryObservations {
    #[cfg(target_os="macos")]
    if !env.dev {
        let intent=match crate::deploy::preflight::get_console_uid() {
            Some(0)=>AuxiliaryObservation::Inactive,
            None=>AuxiliaryObservation::Unknown,
            Some(uid)=>probe_auxiliary(
            &format!("gui/{uid}/com.enterprise.enclave.intent"),
            &enclave_core::runtime_paths::intent_socket(&env.socket_dir,uid),uid,
            &enclave_core::codesign::CodeRequirement::intent(),
            std::path::Path::new("/Library/LaunchAgents/com.enterprise.enclave.intent.plist"),
        ),
        };
        let browser=probe_auxiliary("system/com.enterprise.enclave.browser",&env.socket_dir.join("browser/browser.sock"),707,
            &enclave_core::codesign::CodeRequirement::browser(),
            std::path::Path::new("/Library/LaunchDaemons/com.enterprise.enclave.browser.plist"));
        return AuxiliaryObservations{intent,browser};
    }
    // Development has no installed launchd role/codesign authority. Explicit
    // default sockets are observable as Unknown, never fake native samples.
    let intent=match std::fs::read_dir(env.socket_dir.join("intent")) {
        Ok(mut entries)=>if entries.next().is_some(){AuxiliaryObservation::Unknown}else{AuxiliaryObservation::Inactive},
        Err(error) if error.kind()==std::io::ErrorKind::NotFound=>AuxiliaryObservation::Inactive,
        Err(_)=>AuxiliaryObservation::Unknown,
    };
    let browser=match env.socket_dir.join("browser/browser.sock").try_exists() {
        Ok(false)=>AuxiliaryObservation::Inactive,
        _=>AuxiliaryObservation::Unknown,
    };
    AuxiliaryObservations{intent,browser}
}

// A successful launchctl response still requires one unambiguous process or
// an explicit inactive state. Nested/duplicate/invalid PIDs remain unknown.
#[cfg(any(target_os="macos",test))]
fn launched_pid(text:&str)->Option<Option<u32>> {
    let pids=text.lines().filter_map(|line|line.trim().strip_prefix("pid = "))
        .map(str::parse::<u32>).collect::<Result<Vec<_>,_>>().ok()?;
    match pids.as_slice() {
        [pid] if *pid>1=>Some(Some(*pid)),
        [] if text.lines().any(|line|matches!(line.trim(),"state = not running"|"state = waiting"|"state = exited"))=>Some(None),
        _=>None,
    }
}

#[cfg(target_os="macos")]
fn probe_auxiliary(label:&str,socket:&std::path::Path,uid:u32,requirement:&enclave_core::codesign::CodeRequirement,plist:&std::path::Path)->AuxiliaryObservation {
    let result=crate::syscmd::command(crate::syscmd::Tool::Launchctl).args(["print",label]).output();
    let Ok(output)=result else{return AuxiliaryObservation::Unknown;};
    if !output.status.success(){return if enclave_core::ipc::geteuid()==0 && matches!(plist.try_exists(),Ok(false)) && matches!(socket.try_exists(),Ok(false)){AuxiliaryObservation::Inactive}else{AuxiliaryObservation::Unknown};}
    let Ok(text)=std::str::from_utf8(&output.stdout) else{return AuxiliaryObservation::Unknown;};
    let Some(pid)=launched_pid(text) else{return AuxiliaryObservation::Unknown;};
    let Some(pid)=pid else{return AuxiliaryObservation::Inactive;};
    let Ok(client)=enclave_core::ipc::Client::connect_verified_deadline(socket,uid,Some(requirement),std::time::Duration::from_millis(500)) else{return AuxiliaryObservation::Unknown;};
    if client.server.pid.and_then(|p|u32::try_from(p).ok())!=Some(pid){return AuxiliaryObservation::Unknown;}
    let Some(bytes)=enclave_core::resource::phys_footprint_for_peer(&client.server,requirement) else{return AuxiliaryObservation::Unknown;};
    AuxiliaryObservation::Sample{uid,expected_uid:uid,pid,bytes,source:enclave_core::resource::FootprintSource::DarwinProcPidRusage}
}

/// Journal delivery describes an acknowledged fsynced record, not merely a
/// connection or queued request. Missing authority/journal never becomes ack.
#[derive(Debug,Clone,serde::Serialize,serde::Deserialize)]
pub enum BreachJournalDelivery {
    /// No measured excess exists (unavailable input is still noncompliant).
    NotRequired,
    /// Auditor acknowledged durable append under its own chain.
    Recorded { /// Auditor's journal line number.
        log_seq:u64 },
    /// No durable acknowledgement; the health result remains unhealthy.
    Failed { /// Fixed error reason, with no raw observations or peer payload.
        reason:String },
}
/// Deliver a measured breach through the existing authenticated auditor socket.
/// Only the root code-authenticated operator is authorized by the server.
pub fn record_breach(env:&crate::ctl::Env,observations:&MemoryObservations)->BreachJournalDelivery {
    if !observations.evaluate().has_breach(){return BreachJournalDelivery::NotRequired;}
    let result=(||->enclave_core::error::EnclaveResult<u64>{
        let requirement=(!env.dev).then(||enclave_core::codesign::CodeRequirement::daemon(enclave_core::daemon::DaemonId::ZkAuditor));
        let mut client=enclave_core::ipc::Client::connect_verified_deadline(
            &env.socket_dir.join(enclave_core::daemon::DaemonId::ZkAuditor.socket_name()),env.uid_of(enclave_core::daemon::DaemonId::ZkAuditor),requirement.as_ref(),std::time::Duration::from_millis(500))?;
        client.set_timeout(Some(std::time::Duration::from_millis(500)))?;
        let response:enclave_zk_auditor::service::ZkResponse=client.call(&enclave_zk_auditor::service::ZkRequest::ReportMemoryBreach(Box::new(observations.clone())))?;
        match response{enclave_zk_auditor::service::ZkResponse::MemoryBreachRecorded{log_seq}=>Ok(log_seq),_=>Err(enclave_core::err!(EIO,"MEMORY_BREACH_ACK_REQUIRED"))}
    })();
    match result{Ok(log_seq)=>BreachJournalDelivery::Recorded{log_seq},Err(error)=>BreachJournalDelivery::Failed{reason:error.reason}}
}
