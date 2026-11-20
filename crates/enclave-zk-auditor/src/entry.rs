//! Daemon entry point (UID 705 `_enclavezk`): argument handling, peer wiring and the
//! service loop, shared by the dedicated binary and `mcp-enclave __daemon`.

use std::sync::Mutex;

use crate::service::{Peers, ZkConfig, ZkRequest, ZkResponse, ZkService};
use enclave_core::daemon::DaemonId;
use enclave_core::error::EnclaveResult;
use enclave_core::ipc::{Client, PreparedCall, RELEASE_TIMEOUT};
use enclave_core::runtime::{resolve, run_service, DaemonArgs};
use serde::{Deserialize, Serialize};

/// Wire-compatible subset of the UID 703 / UID 704 request enums
/// (externally tagged CBOR: variant names must match).
#[derive(Serialize)]
enum CosignRequest<'a> {
    CoSignTombstone {
        slot_rpc_seq: u64,
        boot_epoch_id: &'a str,
    },
}

#[derive(Deserialize)]
enum CosignResponse {
    TombstoneSignature {
        signature: serde_bytes::ByteBuf,
        public_key: serde_bytes::ByteBuf,
    },
}

/// UID 703 `BootEpoch` (wire-compatible subset, GAP-27).
#[derive(Serialize)]
enum EpochRequest {
    BootEpoch,
}

#[derive(Deserialize)]
enum EpochResponse {
    Epoch(enclave_core::seq::BootEpoch),
}

/// UID 703 `FetchWitness` (wire-compatible subset).
#[derive(Serialize)]
enum WitnessRequest<'a> {
    FetchWitness {
        boot_epoch_id: &'a str,
        s_start: u64,
        s_end: u64,
    },
}

#[derive(Deserialize)]
enum WitnessResponse {
    Witness {
        folds: Vec<crate::witness::WitnessFold>,
        next_slot: u64,
    },
}

#[derive(Serialize)]
enum RelayRequest<'a> {
    RelayRollup { frame: &'a serde_bytes::Bytes },
}

struct UdsPeers {
    args: DaemonArgs,
    conns: Mutex<Vec<(DaemonId, Client)>>,
}

impl UdsPeers {
    fn call<Req: Serialize, Resp: serde::de::DeserializeOwned>(
        &self,
        d: DaemonId,
        req: &Req,
    ) -> EnclaveResult<Resp> {
        let mut g = self
            .conns
            .lock()
            .map_err(|_| enclave_core::err!(EIO, "LOCK"))?;
        if !g.iter().any(|(k, _)| *k == d) {
            // `connect` verifies the server's peer UID before any byte is sent.
            g.push((d, self.args.connect(d)?));
        }
        let i = g
            .iter()
            .position(|(k, _)| *k == d)
            .ok_or_else(|| enclave_core::err!(EIO, "NO_CONN"))?;
        let r = g[i].1.call(req);
        if r.is_err() {
            g.remove(i);
        }
        r
    }
}

impl Peers for UdsPeers {
    fn cosign(
        &self,
        who: DaemonId,
        slot: u64,
        boot_epoch_id: &str,
    ) -> EnclaveResult<(Vec<u8>, Vec<u8>)> {
        if !matches!(who, DaemonId::CustodyVault | DaemonId::AgentRuntime) {
            enclave_core::fail!(EACCES, "TOMBSTONE_COSIGNER");
        }
        let CosignResponse::TombstoneSignature {
            signature,
            public_key,
        } = self.call(
            who,
            &CosignRequest::CoSignTombstone {
                slot_rpc_seq: slot,
                boot_epoch_id,
            },
        )?;
        Ok((signature.into_vec(), public_key.into_vec()))
    }
    fn prepare_relay(&self, frame: &[u8]) -> EnclaveResult<PreparedCall> {
        // Authenticate and serialize before the caller's release fence. A
        // dedicated connection avoids waiting for unrelated cached RPCs while
        // holding that fence. Production UID and code pins match DaemonArgs.
        let daemon = DaemonId::SwarmSync;
        let requirement = (!self.args.dev_same_uid)
            .then(|| enclave_core::codesign::CodeRequirement::daemon(daemon));
        let client = Client::connect_verified_deadline(
            &self.args.socket_path(daemon),
            self.args.expected_uid(daemon),
            requirement.as_ref(),
            RELEASE_TIMEOUT,
        )?;
        client.prepare_call(&RelayRequest::RelayRollup {
            frame: serde_bytes::Bytes::new(frame),
        })
    }
    fn boot_epoch(&self) -> EnclaveResult<enclave_core::seq::BootEpoch> {
        let EpochResponse::Epoch(be) =
            self.call(DaemonId::CustodyVault, &EpochRequest::BootEpoch)?;
        Ok(be)
    }
    fn fetch_witness(
        &self,
        boot_epoch_id: &str,
        s_start: u64,
        s_end: u64,
    ) -> EnclaveResult<(Vec<crate::witness::WitnessFold>, u64)> {
        let WitnessResponse::Witness { folds, next_slot } = self.call(
            DaemonId::CustodyVault,
            &WitnessRequest::FetchWitness {
                boot_epoch_id,
                s_start,
                s_end,
            },
        )?;
        Ok((folds, next_slot))
    }
}

#[cfg(feature = "simulation")]
fn check_accelerated_schedule(args: &DaemonArgs) -> EnclaveResult<bool> {
    if args.get("accelerated-schedule").is_some() || args.get("accelerated-heartbeat").is_some() {
        args.check_simulation_allowed()?;
        return Ok(true);
    }
    Ok(false)
}

#[cfg(not(feature = "simulation"))]
fn check_accelerated_schedule(args: &DaemonArgs) -> EnclaveResult<bool> {
    if args.get("accelerated-schedule").is_some() || args.get("accelerated-heartbeat").is_some() {
        return Err(enclave_core::err!(
            EPERM,
            "ACCELERATED_SCHEDULE_NOT_COMPILED",
            "this build has no test-only accelerated heartbeat schedule; rebuild with --features simulation for development"
        ));
    }
    Ok(false)
}

/// Run the daemon until SIGTERM / SIGINT.
pub fn run(args: DaemonArgs) -> EnclaveResult<()> {
    args.bind_deployment_for_daemon(DaemonId::ZkAuditor)?;
    enclave_core::host_config::require_profile_floor(
        &args.socket_dir, args.profile, args.dev_same_uid,
    )?;
    let accelerated = check_accelerated_schedule(&args)?;
    let strike_path = args
        .get("strike-file")
        .map(|s| resolve(&args.socket_dir, s))
        .unwrap_or_else(|| "/var/db/enclave/zk/zk-strikes.json".into());
    // GAP-12: the strike state is a sealed store in the strike file's
    // directory, under the daemon sealing key (SEP-unwrapped on hardware);
    // no MAC key is written beside the counter.
    // The daemon's own `--state-dir` wins (dev mode keeps the legacy strike
    // file in the shared state root); otherwise the strike file's directory.
    let quarantine_dir = args.state_dir.clone().unwrap_or_else(|| {
        strike_path
            .parent()
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| "/var/db/enclave/zk".into())
    });
    let peers = Box::new(UdsPeers {
        args: args.clone(),
        conns: Mutex::new(Vec::new()),
    });
    let mut cfg = ZkConfig::new(args.profile, quarantine_dir.clone());
    cfg.audit_path = args.audit_path(DaemonId::ZkAuditor);
    cfg.journal_dir = args.audit_dir.clone();
    cfg.socket_dir = Some(args.socket_dir.clone());
    // Receiver authority comes from authenticated operator configuration, never
    // from the frame, producer hardware witness or static anchor strings.
    if !args.dev_same_uid {
        let bytes=enclave_core::host_config::fetch_tuf_target(&args.socket_dir,
            crate::receiver_trust::TRUST_TARGET,false)?;
        cfg.receiver_trust=Some(crate::receiver_trust::ReceiverTrust::from_json(&bytes)?);
    } else if let Some(path)=args.get("rollup-trust-file") {
        cfg.receiver_trust=Some(crate::receiver_trust::ReceiverTrust::from_operator_file(std::path::Path::new(path))?);
    }

    if let Some(sigs) = args.get("hardware-batch-anchor-sigs") {
        cfg.hardware_batch_anchor_sigs =
            Some(sigs.split(',').map(|s| s.trim().to_string()).collect());
    } else if args.dev_same_uid && args.profile == enclave_core::profile::Profile::L2 {
        cfg.hardware_batch_anchor_sigs = Some(vec!["3045".into()]);
    }
    if args.dev_same_uid && args.profile == enclave_core::profile::Profile::L3 {
        let keys: Vec<(Vec<u8>, Vec<u8>)> = (0..32)
            .map(|i| {
                (
                    format!("dev-sep-{i}").into_bytes(),
                    format!("dev-yk-{i}").into_bytes(),
                )
            })
            .collect();
        if let Ok(tree) = crate::cohort::CohortTree::build(
            keys.iter()
                .map(|(a, b)| crate::cohort::leaf(a, b))
                .collect(),
        ) {
            if let Ok(path) = tree.path(0) {
                cfg.hardware = Some(crate::relation::HardwareWitness {
                    pk_sep: keys[0].0.clone(),
                    pk_yk: keys[0].1.clone(),
                    path,
                    root: tree.root(),
                    cohort_size: tree.size(),
                });
            }
        }
    }
    let svc = ZkService::start(cfg, peers)?;
    // GAP-16: power / sleep / lock / yank wipe hook
    let svc_wipe = std::sync::Arc::downgrade(&svc);
    enclave_core::power::registry().register("705_zk_wipe", move |_trigger| {
        let Some(svc_wipe) = svc_wipe.upgrade() else { return Ok(()); };
        let op = enclave_core::ipc::PeerCredentials::local(0, 0);
        svc_wipe.handle(&op, ZkRequest::Wipe)?;
        Ok(())
    });
    let _power_mon = enclave_core::power::start_for_profile(
        args.profile, enclave_core::power::darwin::PowerMonitor::start,
    )?;
    // GAP-26: L3 constant-rate heartbeat background thread
    if args.profile == enclave_core::profile::Profile::L3 {
        let hb_svc = svc.clone();
        let heartbeat_admission = args.clone();
        let interval = if accelerated {
            std::time::Duration::from_millis(500)
        } else {
            std::time::Duration::from_secs(3600)
        };
        std::thread::spawn(move || loop {
            let jitter_ms = if accelerated {
                rand::random::<u64>() % 100
            } else {
                (rand::random::<u64>() % 300) * 1000
            };
            std::thread::sleep(interval + std::time::Duration::from_millis(jitter_ms));
            let admitted = enclave_core::host_config::require_profile_floor(
                &heartbeat_admission.socket_dir, heartbeat_admission.profile, heartbeat_admission.dev_same_uid,
            );
            if let Err(e) = admitted.and_then(|_| hb_svc.prove_heartbeat()) {
                eprintln!("L3 heartbeat error: {e}");
            }
        });
    }
    // GAP-10: dedicated witness channel listener for UID 703 streaming
    let stop_witness = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let witness_sock_path =
        std::path::PathBuf::from(&args.socket_dir).join(enclave_core::daemon::WITNESS_SOCKET_NAME);
    if let Some(parent) = witness_sock_path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| enclave_core::err!(EIO, "WITNESS_SOCKET_DIRECTORY"))?;
    }
    let access = if args.dev_same_uid {
        enclave_core::ipc::SocketAccess::OwnerOnly
    } else {
        enclave_core::ipc::SocketAccess::Group {
            gid: enclave_core::daemon::WITNESS_CLIENT_GID,
        }
    };
    let listener = enclave_core::ipc::bind(&witness_sock_path, access)?;
    listener.set_nonblocking(true).map_err(|_| enclave_core::err!(EIO, "WITNESS_LISTENER_NONBLOCKING"))?;
    let w_svc = svc.clone();
    let w_stop = stop_witness.clone();
    let witness_admission = args.clone();
    let witness_worker = std::thread::Builder::new().name("witness-channel".into()).spawn(move || {
        crate::witness::serve_witness_channel_with_mode_and_admission(
            listener, w_svc, w_stop, witness_admission.dev_same_uid, move || {
                enclave_core::host_config::require_profile_floor(
                    &witness_admission.socket_dir, witness_admission.profile, witness_admission.dev_same_uid,
                )
            },
        )
    }).map_err(|_| enclave_core::err!(EIO, "WITNESS_WORKER_START"))?;
    let h = svc.clone();
    let admission = args.clone();
    let result = run_service::<ZkRequest, ZkResponse, _>(
        DaemonId::ZkAuditor,
        &args,
        move |p, r| {
            // Safety cleanup remains available even when trust/config expires.
            if !matches!(&r, ZkRequest::Wipe) {
                enclave_core::host_config::require_profile_floor(
                    &admission.socket_dir, admission.profile, admission.dev_same_uid,
                )?;
            }
            h.handle(p, r)
        },
        || {},
    );
    stop_witness.store(true, std::sync::atomic::Ordering::SeqCst);
    // Active frame I/O is bounded; admission/dispatch have their own existing
    // behavior and are not given a hard shutdown deadline by this join.
    let witness_result = witness_worker.join()
        .map_err(|_| enclave_core::err!(EIO, "WITNESS_WORKER_PANIC"))?;
    result.and(witness_result)
}
