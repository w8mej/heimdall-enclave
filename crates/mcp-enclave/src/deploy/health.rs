//! Fleet health monitoring, memory footprint telemetry, and pf anchor auditing (FS-706 §4.2, D-R4, D-R12).

use serde_json::json;
use std::path::Path;

/// Check daemon status, resident physical footprint, packet filter rules, and outbox/quarantine status.
pub fn run_healthcheck(profile: &str) -> (i32, String, serde_json::Value) {
    let parsed_profile = enclave_core::profile::Profile::parse(profile);
    let env =
        crate::ctl::Env::production(parsed_profile.unwrap_or(enclave_core::profile::Profile::L3));
    let statuses: Vec<_> = enclave_core::daemon::DaemonId::ALL
        .iter()
        .map(|d| (*d, crate::ctl::status_of(&env, *d)))
        .collect();
    let observations=crate::memory::MemoryObservations{daemons:std::array::from_fn(|i|statuses[i].1.as_ref().ok().cloned()),auxiliary:crate::memory::observe_auxiliary(&env)};
    let (memory,mut healthy)=authenticated_health_with_auxiliary(profile,std::array::from_fn(|i|observations.daemons[i].as_ref()),&observations.auxiliary);
    let breach_journal=crate::memory::record_breach(&env,&observations);
    if matches!(breach_journal,crate::memory::BreachJournalDelivery::Failed{..}){healthy=false;}
    // RSS is separate telemetry, never evidence of footprint compliance.
    let actual_memory = statuses.iter().try_fold(0u64, |sum, (_, s)|
        sum.checked_add(s.as_ref().ok()?.rss_bytes));
    let zk_state = statuses
        .iter()
        .find(|(d, _)| d.uid() == 705)
        .and_then(|(_, s)| s.as_ref().ok())
        .map(|s| s.state.as_str());
    let quarantine_latched =
        zk_state.is_some_and(|s| s.split_whitespace().any(|v| v == "quarantine_latched=true"));
    let quarantine_known = zk_state.is_some_and(|s| {
        s.split_whitespace()
            .any(|v| v == "quarantine_latched=false" || v == "quarantine_latched=true")
    });
    let memory_journal_healthy=zk_state.is_some_and(|s|s.split_whitespace().any(|v|v=="memory_breach_audit=ok"));
    healthy &= quarantine_known && !quarantine_latched && memory_journal_healthy;
    let mut daemons = Vec::new();

    // Check primary daemon socket presence
    let primary_daemons = [
        ("com.enterprise.enclave.supervisor", "supervisor", 0),
        ("com.enterprise.enclave.adapter", "adapter", 701),
        ("com.enterprise.enclave.cas", "cas", 702),
        ("com.enterprise.enclave.custody", "custody", 703),
        ("com.enterprise.enclave.ifc", "ifc", 704),
        ("com.enterprise.enclave.zk", "zk", 705),
    ];

    for (label, name, uid) in primary_daemons {
        let sock_path = format!("/var/run/enclave/{name}/{name}.sock");
        let socket_present = Path::new(&sock_path).exists();
        healthy &= socket_present;
        daemons.push(json!({
            "label": label,
            "name": name,
            "uid": uid,
            "socket_present": socket_present,
            "socket": sock_path,
            "optional": false,
        }));
    }

    let broker_required=profile=="L3";
    let broker_ready=statuses.iter().find(|(d,_)|d.uid()==702).and_then(|(_,status)|status.as_ref().ok()).is_some_and(|status|status.state.split_whitespace().any(|token|token=="apfs_broker_ready=true"));
    let mut broker_pid=None;
    #[cfg(target_os="macos")] if broker_required {if let Ok(out)=crate::syscmd::command(crate::syscmd::Tool::Launchctl).args(["print","system/com.enterprise.enclave.apfs-broker"]).output(){if out.status.success(){broker_pid=String::from_utf8_lossy(&out.stdout).lines().find_map(|line|line.trim().strip_prefix("pid = ").and_then(|v|v.parse::<u32>().ok()));}}}
    let broker_rss=broker_pid.and_then(enclave_core::resource::rss_of_pid);
    let broker_footprint=broker_pid.and_then(enclave_core::resource::phys_footprint_of_pid);
    if broker_required {healthy&=broker_ready&&broker_footprint.is_some_and(|n|n>0);daemons.push(json!({"label":"com.enterprise.enclave.apfs-broker","name":"apfs-broker","uid":0,"socket":"/var/run/enclave/apfs-broker/broker.sock","socket_present":Path::new("/var/run/enclave/apfs-broker/broker.sock").exists(),"optional":false,"authenticated_readiness":broker_ready,"pid":broker_pid,"rss_bytes":broker_rss,"phys_footprint_bytes":broker_footprint,"memory_budget_status":"unbudgeted auxiliary; not covered by UID701-705 compliance","native_mount_acceptance":"separate required evidence"}));}
    // Check optional daemons (CDP browser GAP-34 and detached hydration worker D-R8)
    let optional_daemons = [
        ("com.enterprise.enclave.hydrate", "hydrate", 702),
        ("com.enterprise.enclave.browser", "browser", 707),
        (enclave_core::daemon::GATEWAY_IDENTIFIER, "gateway", enclave_core::daemon::GATEWAY_UID),
    ];
    for (label, name, uid) in optional_daemons {
        let sock_path = format!("/var/run/enclave/{name}/{name}.sock");
        let plist_path = format!("/Library/LaunchDaemons/{label}.plist");
        let installed = Path::new(&plist_path).exists();
        let socket_present = Path::new(&sock_path).exists();
        if installed || socket_present {
            daemons.push(json!({
                "label": label,
                "name": name,
                "uid": uid,
                "socket_present": socket_present,
                "socket": sock_path,
                "optional": true,
            }));
        }
    }

    // Check Darwin Packet Filter anchor rules per D-R12 / D-R4
    let mut llm_rules_count = 0;
    let mut cas_rules_count = 0;
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = crate::syscmd::command(crate::syscmd::Tool::Pfctl)
            .args(["-a", crate::pf::LLM_ISOLATION_ANCHOR, "-s", "rules"])
            .output()
        {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout);
                llm_rules_count = s.lines().filter(|l| !l.trim().is_empty()).count();
            }
        }
        if let Ok(out) = crate::syscmd::command(crate::syscmd::Tool::Pfctl)
            .args(["-a", crate::pf::CAS_SWARM_ANCHOR, "-s", "rules"])
            .output()
        {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout);
                cas_rules_count = s.lines().filter(|l| !l.trim().is_empty()).count();
            }
        }
    }
    let total_pf_rules = llm_rules_count + cas_rules_count;
    let llm_isolated = llm_rules_count > 0
        && pf_matches(
            crate::pf::LLM_ISOLATION_ANCHOR,
            &crate::pf::render_llm_isolation_rules(),
        );
    let cas_isolated = cas_rules_count > 0
        && pf_matches(
            crate::pf::CAS_SWARM_ANCHOR,
            &crate::pf::render_cas_swarm_rules(),
        );
    let pf_isolated = llm_isolated && cas_isolated;
    healthy &= pf_isolated;

    // Read only service-owned metadata through authenticated CAS IPC. Missing,
    // busy, unsafe, recovery-required or invalid observation is never empty.
    let outbox = observed_outbox_health(crate::ctl::outbox_diagnostics(&env));
    healthy &= outbox.healthy;

    // Check Hardware Integrity Quarantine status (GAP-10, GAP-12, ADR-012)
    // Quarantine comes from the authenticated auditor Status above; no marker file is trusted.
    if quarantine_latched {
        healthy = false;
    }

    // This CLI process is diagnostic telemetry, outside the daemon budget.
    let current_fp = enclave_core::resource::current_phys_footprint_bytes().unwrap_or(0);
    let fp_mib = current_fp as f64 / (1024.0 * 1024.0);

    // If /var/run/enclave exists but supervisor socket is missing, flag unhealthy
    if Path::new("/var/run/enclave").exists()
        && !Path::new("/var/run/enclave/supervisor/supervisor.sock").exists()
    {
        healthy = false;
    }

    let summary = if quarantine_latched {
        "Enclave host is in HARDWARE_INTEGRITY_QUARANTINE (recovery requires UnquarantineGrant)"
            .to_string()
    } else if outbox.budget_exceeded == Some(true) {
        "Enclave outbox retained logical payload exceeded 100 MiB quota (new events blocked)".to_string()
    } else if !outbox.known {
        "Enclave outbox observation unavailable; queue health is not established".to_string()
    } else if healthy && pf_isolated {
        "Authenticated daemon status, memory bounds, quarantine and canonical pf rules healthy"
            .to_string()
    } else {
        healthy = false;
        "Enclave healthcheck detected stopped daemons, memory breach, or exposed pf anchor"
            .to_string()
    };

    let overall_status = if quarantine_latched {
        "quarantined"
    } else if healthy {
        "healthy"
    } else {
        "unhealthy"
    };

    let exit_code = if healthy { 0 } else { 50 };

    let console_uid = crate::deploy::preflight::get_console_uid();
    let intent_socket = console_uid.map(|uid| enclave_core::runtime_paths::intent_socket(Path::new("/var/run/enclave"), uid));
    let intent_socket_present = intent_socket.as_ref().is_some_and(|path| path.exists());
    let intent_deferred = console_uid.is_none() || console_uid == Some(0);

    (
        exit_code,
        summary,
        json!({
            "overall_status": overall_status,
            "daemons": daemons,
            "intent_agent": {
                "label": "com.enterprise.enclave.intent",
                "console_uid": console_uid,
                "socket_present": intent_socket_present,
                "deferred": intent_deferred
            },
            "quarantine": {
                "latched": quarantine_latched,
                "source": "authenticated UID 705 Status",
                "known": quarantine_known
            },
            "outbox": outbox.value,
            "daemon_rss_bytes": actual_memory,
            "broker_required": broker_required,
            "broker_authenticated_readiness": broker_ready,
            "broker_rss_bytes": broker_rss,
            "fleet_with_broker_rss_bytes": broker_rss.and_then(|rss|actual_memory?.checked_add(rss)),
            "physical_memory": memory,
            "memory_breach_journal":breach_journal,
            "memory_breach_journal_healthy":memory_journal_healthy,
            "auxiliary_budget_acceptance": "intent32MiB/browser64MiB enforced; incomplete fleet acceptance: supervisor/broker ceilings unspecified",
            "phys_footprint_scope": "healthcheck CLI process only",
            "phys_footprint_bytes": current_fp,
            "phys_footprint_mib": fp_mib,
            "pf_rules_count": total_pf_rules,
            "pf_isolated": pf_isolated,
            "pf": {
                "llm_rules_count": llm_rules_count,
                "cas_rules_count": cas_rules_count,
                "total_rules": total_pf_rules,
                "isolated": pf_isolated
            },
            "budgets": {
                "uid_702_705_ceiling_mib": 152.0,
                "steady_state_ceiling_mib": 200.0,
                "active_prompt_ceiling_mib": 232.0
            }
        }),
    )
}

struct OutboxHealth {
    known: bool,
    healthy: bool,
    budget_exceeded: Option<bool>,
    value: serde_json::Value,
}

fn observed_outbox_health(result: enclave_core::error::EnclaveResult<crate::ctl::OutboxDiagnosticsExport>) -> OutboxHealth {
    use enclave_swarm_syncd::outbox::{OutboxObservation, DEFAULT_MAX_OUTBOX_BYTES};
    let mut known = false;
    let mut budget_exceeded = None;
    let mut value = json!({
        "source": "kernel-authenticated CAS configured queue metadata",
        "path": null,
        "known": false,
        "queued_frames": null,
        "dead_frames": null,
        "disk_bytes": null,
        "disk_bytes_scope": "retained pending plus dead logical payload lengths; not allocated disk blocks",
        "cap_bytes": DEFAULT_MAX_OUTBOX_BYTES,
        "cap_mib": 100.0,
        "budget_exceeded": null,
        "fault": "acquisition_unavailable",
        "diagnostics": null
    });
    if let Ok(export) = result {
        match export.snapshot.observation {
            OutboxObservation::Current { counts } => {
                known = true;
                let exceeded = counts.retained_bytes > DEFAULT_MAX_OUTBOX_BYTES;
                budget_exceeded = Some(exceeded);
                value["known"] = json!(true);
                value["queued_frames"] = json!(counts.pending_frames);
                value["dead_frames"] = json!(counts.dead_frames);
                value["disk_bytes"] = json!(counts.retained_bytes);
                value["budget_exceeded"] = json!(exceeded);
                value["fault"] = serde_json::Value::Null;
            },
            OutboxObservation::Unavailable { fault } => {
                value["fault"] = json!(fault);
            },
        }
        value["diagnostics"] = json!(export);
    }
    OutboxHealth { known, healthy: known && budget_exceeded == Some(false), budget_exceeded, value }
}

/// Required daemon-memory/profile conjunction, shared with bounded caller checks.
pub(crate) fn authenticated_health(profile: &str, statuses: [Option<&enclave_core::ipc::DaemonStatus>; 5])
    -> (crate::memory::MemoryBudget, bool)
{
    authenticated_health_with_auxiliary(profile,statuses,&crate::memory::AuxiliaryObservations::default())
}

pub(crate) fn authenticated_health_with_auxiliary(profile:&str,statuses:[Option<&enclave_core::ipc::DaemonStatus>;5],auxiliary:&crate::memory::AuxiliaryObservations)->(crate::memory::MemoryBudget,bool) {
    let memory = crate::memory::evaluate_with_auxiliary(statuses,auxiliary);
    let healthy = enclave_core::profile::Profile::parse(profile).is_ok() && memory.compliant
        && statuses.iter().all(|s| s.is_some_and(|s|
            s.state.split_whitespace().any(|token| token == format!("profile={profile}"))));
    (memory, healthy)
}

fn pf_matches(anchor: &str, expected: &str) -> bool {
    #[cfg(target_os = "macos")]
    {
        let path = std::env::temp_dir().join(format!("depot-pf-{}", enclave_core::rng::u64()));
        if enclave_core::fsutil::write_private(&path, expected.as_bytes()).is_err() {
            return false;
        }
        let compiled = crate::syscmd::command(crate::syscmd::Tool::Pfctl)
            .arg("-nvf")
            .arg(&path)
            .output();
        let _ = std::fs::remove_file(&path);
        let live = crate::syscmd::command(crate::syscmd::Tool::Pfctl)
            .args(["-a", anchor, "-sr"])
            .output();
        match (compiled, live) {
            (Ok(a), Ok(b)) if a.status.success() && b.status.success() => {
                let a = normalize_rules(&String::from_utf8_lossy(&a.stdout));
                let b = normalize_rules(&String::from_utf8_lossy(&b.stdout));
                !a.is_empty() && a == b
            }
            _ => false,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (anchor, expected);
        false
    }
}
fn normalize_rules(s: &str) -> Vec<String> {
    s.lines()
        .map(str::trim)
        .filter(|l| {
            [
                "pass ", "block ", "match ", "scrub ", "nat ", "rdr ", "anchor ",
            ]
            .iter()
            .any(|p| l.starts_with(p))
        })
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect()
}
#[cfg(test)]
mod f112_tests {
    use super::*;
    #[test]
    fn never_installed_is_unhealthy_and_rule_content_matters() {
        #[cfg(not(target_os = "macos"))]
        assert_eq!(run_healthcheck("L2").0, 50);
        assert_eq!(
            normalize_rules(
                "# comments
pass  out quick
"
            ),
            vec!["pass out quick"]
        );
        assert_ne!(
            normalize_rules("pass out quick"),
            normalize_rules("block out quick")
        );
    }
}

#[cfg(test)]
#[path = "outbox_health_boundary_tests.rs"]
mod outbox_health_boundary_tests;
