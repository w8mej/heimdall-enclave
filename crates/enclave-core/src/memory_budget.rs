//! Shared physical-footprint decisions for authenticated daemon observations.

use crate::{daemon::DaemonId, ipc::DaemonStatus};
use serde::{Deserialize, Serialize};

const MIB: u64 = 1024 * 1024;

/// Per-daemon decision in fixed UID order. Missing/zero/legacy readings are unknown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonBudget {
    /// Production UID.
    pub uid: u32,
    /// Genuine physical footprint, when available.
    pub bytes: Option<u64>,
    /// Original reported numeric value, including unusable legacy samples.
    pub reported_bytes: Option<u64>,
    /// Reported API provenance, defaulting to unknown.
    pub source: crate::resource::FootprintSource,
    /// RSS is diagnostic only.
    pub rss_bytes: Option<u64>,
    /// Inclusive individual ceiling.
    pub ceiling_bytes: u64,
    /// Unknown cannot satisfy a ceiling.
    pub within_ceiling: bool,
}

/// Exact-byte budget result. Totals are absent on missing input or overflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryBudget {
    /// Individual decisions, including all five required daemons.
    pub daemons: Vec<DaemonBudget>,
    /// UID 701–705 total.
    pub total_bytes: Option<u64>,
    /// UID 702–705 total.
    pub other_bytes: Option<u64>,
    /// At least one required observation is unavailable or untrusted.
    pub unknown_required: bool,
    /// At least one sum exceeded the integer representation.
    pub overflow: bool,
    /// Every required observation and individual/aggregate ceiling passed.
    pub compliant: bool,
    /// Explicit intent/browser decisions. Browser is separate from200/232MiB.
    pub auxiliary:Vec<AuxiliaryBudget>,
    /// Five daemons plus resident intent process; None if either is unknown.
    pub active_prompt_bytes:Option<u64>,
    /// Five daemons, intent and browser total, for telemetry only; no invented cap.
    pub specified_process_bytes:Option<u64>,
}

/// Evaluate exactly one authenticated Status per required daemon. Position and
/// reported UID must agree; reported ceilings never override local policy.
pub fn evaluate(statuses: [Option<&DaemonStatus>; 5]) -> MemoryBudget {
    evaluate_with_auxiliary(statuses,&AuxiliaryObservations::default())
}
/// Evaluate five-daemon, active-intent and separate browser envelopes together.
/// Supervisor/broker have no specified ceiling and are deliberately outside
/// this policy; satisfying it does not establish complete fleet acceptance.
pub fn evaluate_with_auxiliary(statuses:[Option<&DaemonStatus>;5],observations:&AuxiliaryObservations)->MemoryBudget {
    let daemons: Vec<_> = DaemonId::ALL
        .into_iter()
        .zip(statuses)
        .map(|(d, s)| {
            let bytes = s
                .filter(|s| {
                    s.daemon_uid == d.uid()
                        && s.phys_footprint_source.is_physical()
                        && s.phys_footprint_bytes > 0
                })
                .map(|s| s.phys_footprint_bytes);
            DaemonBudget {
                uid: d.uid(),
                bytes,
                reported_bytes: s.map(|s| s.phys_footprint_bytes),
                source: s.map(|s| s.phys_footprint_source).unwrap_or_default(),
                rss_bytes: s.map(|s| s.rss_bytes),
                ceiling_bytes: d.rss_ceiling_bytes(),
                within_ceiling: bytes.is_some_and(|n| n <= d.rss_ceiling_bytes()),
            }
        })
        .collect();
    let auxiliary:Vec<_>=[("intent",32*MIB,&observations.intent),("browser",64*MIB,&observations.browser)].into_iter().map(|(role,ceiling_bytes,observation)| {
        let inactive=matches!(observation,AuxiliaryObservation::Inactive);
        let bytes=match observation {
            AuxiliaryObservation::Inactive=>Some(0),
            AuxiliaryObservation::Sample{uid,expected_uid,pid,bytes,source} if uid==expected_uid && *pid>1 && *bytes>0 && source.is_physical()
                && (if role=="browser" {*uid==707}else{*uid>0&&!matches!(*uid,701..=708)})=>Some(*bytes),
            _=>None,
        };
        AuxiliaryBudget{role:role.into(),inactive,bytes,ceiling_bytes,within_ceiling:bytes.is_some_and(|b|b<=ceiling_bytes)}
    }).collect();
    let unknown_required = daemons.iter().any(|d| d.bytes.is_none())||auxiliary.iter().any(|a|a.bytes.is_none());
    let sum = |skip| {
        let mut total = Some(0u64);
        let mut unknown = false;
        for d in daemons.iter().skip(skip) {
            match d.bytes {
                Some(bytes) => total = total.and_then(|n| n.checked_add(bytes)),
                None => unknown = true,
            }
        }
        (if unknown { None } else { total }, total.is_none())
    };
    let (total_bytes, total_overflow) = sum(0);
    let (other_bytes, other_overflow) = sum(1);
    let active_prompt_bytes=total_bytes.and_then(|b|b.checked_add(auxiliary[0].bytes?));
    let specified_process_bytes=active_prompt_bytes.and_then(|b|b.checked_add(auxiliary[1].bytes?));
    let auxiliary_overflow=total_bytes.zip(auxiliary[0].bytes).is_some_and(|(a,b)|a.checked_add(b).is_none())
        ||active_prompt_bytes.zip(auxiliary[1].bytes).is_some_and(|(a,b)|a.checked_add(b).is_none());
    let overflow = total_overflow || other_overflow || auxiliary_overflow;
    let compliant = !unknown_required
        && !overflow
        && daemons.iter().all(|d| d.within_ceiling)
        && auxiliary.iter().all(|a|a.within_ceiling)
        && active_prompt_bytes.is_some_and(|b|b<=232*MIB)
        && total_bytes.is_some_and(|n| n <= 200 * MIB)
        && other_bytes.is_some_and(|n| n <= 152 * MIB);
    MemoryBudget {
        daemons,
        total_bytes,
        other_bytes,
        unknown_required,
        overflow,
        compliant,auxiliary,active_prompt_bytes,specified_process_bytes,
    }
}


/// Observation of one optional process. Inactive requires a successful launchd
/// observation (or no configured session/job); failed probes are Unknown.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AuxiliaryObservation {
    /// No process is running in the selected configured role.
    Inactive,
    /// Presence, identity or genuine physical footprint could not be established.
    Unknown,
    /// Kernel credentials and code identity were checked around native sampling.
    Sample {
        /// Kernel effective UID.
        uid:u32,
        /// Locally selected role UID (console user for intent,707 for browser).
        expected_uid:u32,
        /// Kernel-authenticated process identifier.
        pid:u32,
        /// Genuine footprint reading.
        bytes:u64,
        /// Reading provenance; RSS is never accepted.
        source:crate::resource::FootprintSource,
    },
}
/// Fixed auxiliary roles; callers cannot choose a role's resource ceiling.
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuxiliaryObservations {
    /// Resident on-demand intent process, limited to32MiB.
    pub intent:AuxiliaryObservation,
    /// Optional browser, separately limited to64MiB.
    pub browser:AuxiliaryObservation,
}
impl Default for AuxiliaryObservations {
    fn default()->Self {Self{intent:AuxiliaryObservation::Inactive,browser:AuxiliaryObservation::Inactive}}
}
/// Decision for an optional process, outside the fixed five-daemon total.
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct AuxiliaryBudget {
    /// Fixed role name.
    pub role:String,
    /// Whether the role is known inactive.
    pub inactive:bool,
    /// Footprint, including zero for a known inactive role; None means unknown.
    pub bytes:Option<u64>,
    /// Fixed specification ceiling.
    pub ceiling_bytes:u64,
    /// Known inactive or a valid sample at/below its fixed ceiling.
    pub within_ceiling:bool,
}
/// Bounded root-operator observations delivered to the auditor. They are an
/// authenticated operator report, not a claim that UID705 sampled its siblings.
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryObservations {
    /// One authenticated Status per fixed daemon, in UID701–705 order.
    pub daemons:[Option<DaemonStatus>;5],
    /// Explicit auxiliary observations.
    pub auxiliary:AuxiliaryObservations,
}
impl MemoryObservations {
    /// Recompute all fixed specification policy; no client-supplied ceilings.
    pub fn evaluate(&self)->MemoryBudget {
        evaluate_with_auxiliary(std::array::from_fn(|i|self.daemons[i].as_ref()),&self.auxiliary)
    }
}
impl MemoryBudget {
    /// A measured excess or known arithmetic overflow, as distinct from an
    /// unavailable observation. Unknown still makes compliant false.
    pub fn has_breach(&self)->bool {
        self.overflow || self.daemons.iter().any(|d|d.bytes.is_some_and(|b|b>d.ceiling_bytes))
            || self.total_bytes.is_some_and(|b|b>200*MIB)
            || self.other_bytes.is_some_and(|b|b>152*MIB)
            || self.auxiliary.iter().any(|d|d.bytes.is_some_and(|b|b>d.ceiling_bytes))
            || self.active_prompt_bytes.is_some_and(|b|b>232*MIB)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn statuses()->[DaemonStatus;5]{DaemonId::ALL.map(|d|DaemonStatus{
        daemon_uid:d.uid(),binary:d.binary().into(),pid:123,rss_bytes:u64::MAX,rss_ceiling_bytes:u64::MAX,
        boot_epoch_id:String::new(),rpc_seq_u64:0,state:String::new(),phys_footprint_bytes:d.rss_ceiling_bytes(),
        phys_footprint_source:crate::resource::FootprintSource::DarwinTaskVmInfo,
    })}
    fn sample(uid:u32,bytes:u64)->AuxiliaryObservation{AuxiliaryObservation::Sample{uid,expected_uid:uid,pid:123,bytes,source:crate::resource::FootprintSource::DarwinProcPidRusage}}
    #[test]
    fn memory_auxiliary_exact_caps_active_prompt_and_separate_browser() {
        let s=statuses();let mut auxiliary=AuxiliaryObservations{intent:sample(501,32*MIB),browser:sample(707,64*MIB)};
        let evaluate=|a:&AuxiliaryObservations|evaluate_with_auxiliary(std::array::from_fn(|i|Some(&s[i])),a);
        let b=evaluate(&auxiliary);assert!(b.compliant&&!b.has_breach());assert_eq!(b.total_bytes,Some(200*MIB));assert_eq!(b.active_prompt_bytes,Some(232*MIB));assert_eq!(b.specified_process_bytes,Some(296*MIB));
        auxiliary.intent=sample(501,32*MIB+1);assert!(!evaluate(&auxiliary).compliant&&evaluate(&auxiliary).has_breach());
        auxiliary.intent=sample(501,1);auxiliary.browser=sample(707,64*MIB+1);assert!(evaluate(&auxiliary).has_breach());
    }
    #[test]
    fn memory_auxiliary_unknown_zero_wrong_identity_and_overflow_refuse() {
        let s=statuses();let evaluate=|intent,browser|evaluate_with_auxiliary(std::array::from_fn(|i|Some(&s[i])),&AuxiliaryObservations{intent,browser});
        for observation in [AuxiliaryObservation::Unknown,sample(501,0),sample(703,1),AuxiliaryObservation::Sample{uid:501,expected_uid:502,pid:123,bytes:1,source:crate::resource::FootprintSource::DarwinProcPidRusage},AuxiliaryObservation::Sample{uid:501,expected_uid:501,pid:123,bytes:1,source:crate::resource::FootprintSource::Unknown}] {
            let b=evaluate(observation,AuxiliaryObservation::Inactive);assert!(b.unknown_required&&!b.compliant&&!b.has_breach());
        }
        let b=evaluate(AuxiliaryObservation::Inactive,sample(501,1));assert!(b.unknown_required&&!b.compliant);
        let b=evaluate(sample(501,u64::MAX),sample(707,1));assert!(b.overflow&&b.has_breach()&&!b.compliant);assert_eq!(b.active_prompt_bytes,None);
    }
}
