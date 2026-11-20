//! Fixed local call-result diagnostics, reset on daemon-process initialization.
//!
//! These counters describe four service call boundaries, never synchronization
//! SLO units, delivery, elapsed history, or installed production acceptance.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;
use serde::{Deserialize, Serialize};

/// Inclusive diagnostic counter ceiling.
pub const MAX_COUNT: u64 = 1_000_000_000_000_000;
/// Exact diagnostic schema producer.
pub const PRODUCER: &str = "uid702-local-sync-stages-v1";

/// One fixed local stage's mutually exclusive lifecycle counters.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageCounters {
    /// Calls whose stage boundary was entered.
    pub started: u64,
    /// Calls without a known final local result yet.
    pub in_flight: u64,
    /// Calls that locally returned `Ok`, without asserting delivery.
    pub returned_ok: u64,
    /// Calls that locally returned `Err`.
    pub returned_err: u64,
    /// Guards dropped without a final result, including ordinary unwinding.
    pub abandoned_unknown: u64,
}
impl StageCounters {
    /// Check the fixed ceiling and exact lifecycle conservation.
    pub fn valid(&self) -> bool {
        [self.started,self.in_flight,self.returned_ok,self.returned_err,self.abandoned_unknown]
            .into_iter().all(|v| v <= MAX_COUNT)
            && self.in_flight.checked_add(self.returned_ok)
                .and_then(|n| n.checked_add(self.returned_err))
                .and_then(|n| n.checked_add(self.abandoned_unknown)) == Some(self.started)
    }
}

/// The complete fixed set of stages; no caller-controlled labels or map growth.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageRecords {
    /// Final committing TUF handler outcome, including later journal work.
    pub tuf_refresh: StageCounters,
    /// One actual registry fetch invocation's local return.
    pub registry_fetch: StageCounters,
    /// One actual authenticated QUIC fetch invocation's local return.
    pub quic_fetch: StageCounters,
    /// One actual RFC OHTTP fetch invocation's local return.
    pub ohttp_fetch: StageCounters,
}
impl StageRecords {
    /// Validate all four fixed records.
    pub fn valid(&self) -> bool {
        [self.tuf_refresh,self.registry_fetch,self.quic_fetch,self.ohttp_fetch]
            .iter().all(StageCounters::valid)
    }
    fn stage_mut(&mut self, stage: Stage) -> &mut StageCounters {
        match stage {Stage::TufRefresh=>&mut self.tuf_refresh,Stage::RegistryFetch=>&mut self.registry_fetch,
            Stage::QuicFetch=>&mut self.quic_fetch,Stage::OhttpFetch=>&mut self.ohttp_fetch}
    }
}

const OVERFLOW: u8 = 1;
const UNDERFLOW: u8 = 2;
const POISONED: u8 = 4;
const INCONSISTENT: u8 = 8;

/// Fixed fault signals, latched until this collector is destroyed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementFaults {
    /// A mutation would exceed the inclusive count ceiling.
    pub overflow: bool,
    /// A completion had no matching in-flight count.
    pub underflow: bool,
    /// The collector mutex was poisoned; protected values were not recovered.
    pub poisoned: bool,
    /// Protected values failed their bounded conservation invariant.
    pub inconsistent: bool,
}
impl MeasurementFaults {
    fn from_bits(bits: u8) -> Self {Self {overflow:bits&OVERFLOW!=0,underflow:bits&UNDERFLOW!=0,
        poisoned:bits&POISONED!=0,inconsistent:bits&INCONSISTENT!=0}}
    /// Whether any measurement failure has occurred.
    pub fn any(&self) -> bool {self.overflow||self.underflow||self.poisoned||self.inconsistent}
}

/// Provenance of the optional counter values in a diagnostic snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="snake_case")]
pub enum CounterAvailability {
    /// Valid current counters without a measurement fault.
    Current,
    /// Last valid counters, frozen at an arithmetic fault; never current health.
    LastKnown,
    /// No trustworthy counters can be copied; values are absent, never zeros.
    Unavailable,
}

/// Bounded, service-owned snapshot; the epoch is server-supplied process identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncDiagnosticsSnapshot {
    /// Wire schema, exactly one.
    pub schema: u32,
    /// Fixed producer string.
    pub producer: String,
    /// Existing local process-initialization epoch, not OS or SEP attestation.
    pub process_epoch_id: String,
    /// Actual process effective UID captured at initialization.
    pub process_uid: u32,
    /// Actual process PID captured at initialization.
    pub process_pid: u32,
    /// Explicit trusted startup mode, never inferred from UID or backend.
    pub dev_same_uid: bool,
    /// Latched fixed measurement faults.
    pub measurement_fault: MeasurementFaults,
    /// Whether optional records are current, last known, or unavailable.
    pub availability: CounterAvailability,
    /// Exactly four records when trustworthy values remain available.
    pub stages: Option<StageRecords>,
}
impl SyncDiagnosticsSnapshot {
    /// Validate bounded counters and their fault/availability provenance.
    pub fn valid_measurement(&self) -> bool {
        match (self.availability,self.stages) {
            (CounterAvailability::Current,Some(values))=>!self.measurement_fault.any()&&values.valid(),
            (CounterAvailability::LastKnown,Some(values))=>self.measurement_fault.any()
                && !self.measurement_fault.poisoned&&!self.measurement_fault.inconsistent&&values.valid(),
            (CounterAvailability::Unavailable,None)=>self.measurement_fault.poisoned||self.measurement_fault.inconsistent,
            _=>false,
        }
    }
}

#[derive(Debug,Clone,Copy)]
pub(crate) enum Stage {TufRefresh,RegistryFetch,QuicFetch,OhttpFetch}
#[derive(Debug,Clone,Copy)]
enum Outcome {Ok,Err,Unknown}

/// Fixed service collector. Its mutex never crosses a callback or authority work.
#[derive(Debug)]
pub(crate) struct SyncDiagnostics {
    process_epoch_id:String,
    process_uid:u32,
    process_pid:u32,
    dev_same_uid:bool,
    faults:AtomicU8,
    records:Mutex<StageRecords>,
}
impl SyncDiagnostics {
    pub(crate) fn new(process_epoch_id:String,dev_same_uid:bool)->Self {
        Self {process_epoch_id,process_uid:enclave_core::ipc::geteuid(),process_pid:std::process::id(),
            dev_same_uid,faults:AtomicU8::new(0),records:Mutex::new(StageRecords::default())}
    }
    pub(crate) fn authorized(&self,peer_uid:u32)->bool {
        if self.dev_same_uid {peer_uid==self.process_uid}else{peer_uid==0}
    }
    fn fault(&self,bits:u8){self.faults.fetch_or(bits,Ordering::SeqCst);}
    #[cfg(test)]
    pub(crate) fn poison_for_test(&self) {
        let _=std::panic::catch_unwind(||{let _lock=self.records.lock().unwrap();panic!("owned telemetry poison fixture");});
    }
    pub(crate) fn start(&self,stage:Stage)->Operation<'_> {
        let mut active=false;
        if self.faults.load(Ordering::SeqCst)==0 {
            match self.records.lock() {
                Err(_)=>self.fault(POISONED),
                Ok(mut records)=>{
                    if !records.valid(){self.fault(INCONSISTENT);}
                    else if self.faults.load(Ordering::SeqCst)==0 {
                        let current=records.stage_mut(stage);
                        match (current.started.checked_add(1),current.in_flight.checked_add(1)) {
                            (Some(started),Some(in_flight)) if started<=MAX_COUNT&&in_flight<=MAX_COUNT=>{
                                current.started=started;current.in_flight=in_flight;active=true;
                            }
                            _=>self.fault(OVERFLOW),
                        }
                    }
                }
            }
        }
        Operation {collector:self,stage,active}
    }
    fn finish(&self,stage:Stage,outcome:Outcome) {
        if self.faults.load(Ordering::SeqCst)!=0{return;}
        match self.records.lock() {
            Err(_)=>self.fault(POISONED),
            Ok(mut records)=>{
                if self.faults.load(Ordering::SeqCst)!=0{return;}
                let current=records.stage_mut(stage);
                // Detect underflow explicitly before conservation validation.
                if current.in_flight==0 {self.fault(UNDERFLOW);return;}
                if !records.valid(){self.fault(INCONSISTENT);return;}
                let current=records.stage_mut(stage);let mut next=*current;
                let count=match outcome {Outcome::Ok=>&mut next.returned_ok,Outcome::Err=>&mut next.returned_err,
                    Outcome::Unknown=>&mut next.abandoned_unknown};
                let Some(value)=count.checked_add(1).filter(|v|*v<=MAX_COUNT) else {self.fault(OVERFLOW);return;};
                *count=value;
                let Some(in_flight)=next.in_flight.checked_sub(1) else {self.fault(UNDERFLOW);return;};
                next.in_flight=in_flight;
                if !next.valid(){self.fault(INCONSISTENT);return;}
                *current=next;
            }
        }
    }
    pub(crate) fn snapshot(&self)->SyncDiagnosticsSnapshot {
        let (faults,stages)=match self.records.lock() {
            Err(_)=>{self.fault(POISONED);(self.faults.load(Ordering::SeqCst),None)},
            Ok(records)=>{
                if !records.valid(){self.fault(INCONSISTENT);}
                let faults=self.faults.load(Ordering::SeqCst);
                let stages=if faults&(POISONED|INCONSISTENT)!=0 {None}else{Some(*records)};
                (faults,stages)
            }
        };
        SyncDiagnosticsSnapshot {schema:1,producer:PRODUCER.into(),process_epoch_id:self.process_epoch_id.clone(),
            process_uid:self.process_uid,process_pid:self.process_pid,dev_same_uid:self.dev_same_uid,
            measurement_fault:MeasurementFaults::from_bits(faults),
            availability:if stages.is_none(){CounterAvailability::Unavailable}else if faults!=0{CounterAvailability::LastKnown}else{CounterAvailability::Current},stages}
    }
}

/// Non-cloneable, exactly-once operation lifetime. Drop cannot propagate failure.
#[derive(Debug)]
pub(crate) struct Operation<'a> {collector:&'a SyncDiagnostics,stage:Stage,active:bool}
impl Operation<'_> {
    pub(crate) fn finish(mut self,returned_ok:bool) {
        if self.active {self.active=false;self.collector.finish(self.stage,if returned_ok{Outcome::Ok}else{Outcome::Err});}
    }
}
impl Drop for Operation<'_> {
    fn drop(&mut self) {if self.active{self.active=false;self.collector.finish(self.stage,Outcome::Unknown);}}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn collector()->SyncDiagnostics {SyncDiagnostics::new(enclave_core::seq::new_boot_epoch_id(),true)}
    fn current(collector:&SyncDiagnostics)->StageRecords {
        let snapshot=collector.snapshot();assert!(snapshot.valid_measurement());
        assert_eq!(snapshot.availability,CounterAvailability::Current);snapshot.stages.unwrap()
    }

    #[test]
    fn diagnostics_finish_drop_and_caught_unwind_finalize_once_without_false_ok() {
        let collector=collector();
        collector.start(Stage::TufRefresh).finish(true);
        collector.start(Stage::TufRefresh).finish(false);
        drop(collector.start(Stage::TufRefresh));
        let caught=std::panic::catch_unwind(||{let _stage=collector.start(Stage::TufRefresh);panic!("owned unwind fixture");});
        assert!(caught.is_err());
        assert_eq!(current(&collector).tuf_refresh,StageCounters {started:4,in_flight:0,returned_ok:1,returned_err:1,abandoned_unknown:2});
    }

    #[test]
    fn diagnostics_concurrent_snapshots_and_inflight_barrier_conserve_all_stages() {
        let collector=Arc::new(collector());let barrier=Arc::new(std::sync::Barrier::new(5));
        let mut workers=Vec::new();
        for stage in [Stage::TufRefresh,Stage::RegistryFetch,Stage::QuicFetch,Stage::OhttpFetch] {
            let collector=collector.clone();let barrier=barrier.clone();
            workers.push(std::thread::spawn(move||{
                let active=collector.start(stage);barrier.wait();barrier.wait();active.finish(true);
                for i in 0..200 {collector.start(stage).finish(i%2==0);}
            }));
        }
        barrier.wait();let live=current(&collector);
        for record in [live.tuf_refresh,live.registry_fetch,live.quic_fetch,live.ohttp_fetch] {
            assert_eq!(record,StageCounters {started:1,in_flight:1,..StageCounters::default()});
        }
        barrier.wait();
        for _ in 0..200 {assert!(collector.snapshot().valid_measurement());std::thread::yield_now();}
        for worker in workers {worker.join().unwrap();}
        let final_counts=current(&collector);
        for record in [final_counts.tuf_refresh,final_counts.registry_fetch,final_counts.quic_fetch,final_counts.ohttp_fetch] {
            assert_eq!(record,StageCounters {started:201,in_flight:0,returned_ok:101,returned_err:100,abandoned_unknown:0});
        }
    }

    #[test]
    fn diagnostics_ceiling_and_underflow_latch_atomic_last_known_values() {
        let collector=collector();
        let maximum=StageCounters {started:MAX_COUNT,returned_ok:MAX_COUNT,..StageCounters::default()};
        collector.records.lock().unwrap().tuf_refresh=maximum;
        let before=collector.snapshot();assert!(before.valid_measurement());
        collector.start(Stage::TufRefresh).finish(true);
        let fault=collector.snapshot();assert!(fault.valid_measurement());
        assert!(fault.measurement_fault.overflow);assert_eq!(fault.availability,CounterAvailability::LastKnown);
        assert_eq!(fault.stages,before.stages);
        collector.start(Stage::RegistryFetch).finish(false);
        assert_eq!(collector.snapshot(),fault,"latched faults freeze last-known values");
        let underflow=super::SyncDiagnostics::new(enclave_core::seq::new_boot_epoch_id(),true);
        underflow.finish(Stage::QuicFetch,Outcome::Err);
        let snapshot=underflow.snapshot();assert!(snapshot.valid_measurement());assert!(snapshot.measurement_fault.underflow);
        assert_eq!(snapshot.availability,CounterAvailability::LastKnown);
        assert_eq!(snapshot.stages,Some(StageRecords::default()),"these are retained valid values, not unavailable replacement zeros");
    }

    #[test]
    fn diagnostics_poison_and_inconsistent_values_are_unavailable_never_fabricated_zero() {
        let collector=collector();let stage=collector.start(Stage::RegistryFetch);
        let caught=std::panic::catch_unwind(||{let _lock=collector.records.lock().unwrap();panic!("owned poison fixture");});
        assert!(caught.is_err());drop(stage);
        let poisoned=collector.snapshot();assert!(poisoned.valid_measurement());
        assert!(poisoned.measurement_fault.poisoned);assert_eq!(poisoned.availability,CounterAvailability::Unavailable);assert_eq!(poisoned.stages,None);
        assert_eq!(collector.snapshot(),poisoned);
        let inconsistent=super::SyncDiagnostics::new(enclave_core::seq::new_boot_epoch_id(),true);
        inconsistent.records.lock().unwrap().quic_fetch.started=1;
        let snapshot=inconsistent.snapshot();assert!(snapshot.valid_measurement());assert!(snapshot.measurement_fault.inconsistent);
        assert_eq!(snapshot.availability,CounterAvailability::Unavailable);assert!(snapshot.stages.is_none());
    }

    #[test]
    fn diagnostics_authorization_uses_explicit_mutually_exclusive_modes() {
        let mut dev=collector();dev.process_uid=501;
        assert!(dev.authorized(501));assert!(!dev.authorized(0));assert!(!dev.authorized(702));
        let mut production=collector();production.process_uid=702;production.dev_same_uid=false;
        assert!(production.authorized(0));for uid in [501,701,702,703,704,705] {assert!(!production.authorized(uid));}
    }

    #[test]
    fn diagnostics_maximum_reply_is_bounded_and_unknown_wire_fields_are_refused() {
        let collector=collector();let maximum=StageCounters {started:MAX_COUNT,returned_ok:MAX_COUNT,..StageCounters::default()};
        *collector.records.lock().unwrap()=StageRecords {tuf_refresh:maximum,registry_fetch:maximum,quic_fetch:maximum,ohttp_fetch:maximum};
        let mut snapshot=collector.snapshot();snapshot.process_uid=u32::MAX;snapshot.process_pid=u32::MAX;
        assert!(snapshot.valid_measurement());
        let response=crate::service::CasResponse::SyncDiagnostics(snapshot.clone());
        let cbor=enclave_core::ipc::to_cbor(&enclave_core::ipc::Reply::Ok(response.clone())).unwrap();
        let json=serde_json::to_vec(&response).unwrap();
        assert!(cbor.len()<enclave_core::ipc::MAX_FRAME&&json.len()<enclave_core::ipc::MAX_FRAME);
        assert!(cbor.len()<4096&&json.len()<4096,"fixed metadata and records remain small");
        let mut value=serde_json::to_value(snapshot).unwrap();value["target_inventory"]=serde_json::json!(["must-refuse"]);
        assert!(serde_json::from_value::<SyncDiagnosticsSnapshot>(value).is_err());
    }

    #[test]
    fn diagnostics_abort_cannot_supply_a_final_outcome_or_inherit_process_coverage() {
        const CHILD:&str="depot_STAGE_DIAGNOSTICS_ABORT_FIXTURE";
        if std::env::var_os(CHILD).is_some() {
            // This owned child must never write a core file on the shared disk.
            let limit=libc::rlimit {rlim_cur:0,rlim_max:0};assert_eq!(unsafe{libc::setrlimit(libc::RLIMIT_CORE,&limit)},0);
            let collector=collector();let _stage=collector.start(Stage::OhttpFetch);
            use std::io::Write;
            println!("DIAGNOSTICS_PRE_ABORT={}",serde_json::to_string(&collector.snapshot()).unwrap());
            std::io::stdout().flush().unwrap();std::process::abort();
        }
        struct OwnedChild(Option<std::process::Child>);
        impl Drop for OwnedChild {fn drop(&mut self){if let Some(mut child)=self.0.take(){let _=child.kill();let _=child.wait();}}}
        let mut child=OwnedChild(Some(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact","sync_diagnostics::tests::diagnostics_abort_cannot_supply_a_final_outcome_or_inherit_process_coverage","--nocapture"])
            .env(CHILD,"1").stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap()));
        let deadline=std::time::Instant::now()+std::time::Duration::from_secs(10);
        loop {
            if child.0.as_mut().unwrap().try_wait().unwrap().is_some(){break;}
            if std::time::Instant::now()>=deadline {panic!("owned abort child exceeded deadline");}
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let output=child.0.take().unwrap().wait_with_output().unwrap();assert!(!output.status.success());
        let stdout=String::from_utf8(output.stdout).unwrap();let line=stdout.lines().find_map(|line|line.split_once("DIAGNOSTICS_PRE_ABORT=").map(|(_,snapshot)|snapshot)).unwrap();
        let before:SyncDiagnosticsSnapshot=serde_json::from_str(line).unwrap();assert!(before.valid_measurement());
        assert_eq!(before.stages.unwrap().ohttp_fetch,StageCounters {started:1,in_flight:1,..StageCounters::default()});
        let restarted=collector().snapshot();assert_ne!(restarted.process_epoch_id,before.process_epoch_id);
        assert_eq!(restarted.stages,Some(StageRecords::default()));
        // Only the pre-abort state was observed. No destructor outcome is claimed.
    }
}
