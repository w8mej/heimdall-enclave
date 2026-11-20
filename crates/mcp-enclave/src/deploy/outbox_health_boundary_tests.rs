//! Configured-queue health boundaries, referenced privately under cfg(test).
//! Calls the actual CLI acquisition and health adapter over real Unix IPC.
//! Synthetic hostile replies below establish refusal only, not measured health.

use super::observed_outbox_health;
use enclave_core::{
    daemon::DaemonId,
    ipc::{self, Reply},
    profile::Profile,
};
use enclave_swarm_syncd::service::{CasConfig, CasRequest, CasResponse, CasService};
use serde_json::{json, Value};
use std::io::{self, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

const CANARY: &str = "private-outbox/file:///private/path?token=backend-secret";
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("mc-obhealth-{:016x}", enclave_core::rng::u64()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct OwnedWorker(Option<thread::JoinHandle<()>>);
impl OwnedWorker {
    fn join(mut self) {
        self.0.take().unwrap().join().unwrap();
    }
}
impl Drop for OwnedWorker {
    fn drop(&mut self) {
        if let Some(worker) = self.0.take() {
            let _ = worker.join();
        }
    }
}

// Explicit JSON-number serializer avoids arbitrary_precision's private struct
// representation when this test serializes hostile JSON values through CBOR.
struct WireValue<'a>(&'a Value);
impl serde::Serialize for WireValue<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{Error, SerializeMap, SerializeSeq};
        match self.0 {
            Value::Null => serializer.serialize_unit(),
            Value::Bool(value) => serializer.serialize_bool(*value),
            Value::Number(value) => {
                if let Some(value) = value.as_u64() {
                    serializer.serialize_u64(value)
                } else if let Some(value) = value.as_i64() {
                    serializer.serialize_i64(value)
                } else {
                    Err(S::Error::custom(
                        "fixture requires an exact bounded integer",
                    ))
                }
            }
            Value::String(value) => serializer.serialize_str(value),
            Value::Array(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(&WireValue(value))?;
                }
                sequence.end()
            }
            Value::Object(values) => {
                let mut map = serializer.serialize_map(Some(values.len()))?;
                for (key, value) in values {
                    map.serialize_entry(key, &WireValue(value))?;
                }
                map.end()
            }
        }
    }
}

enum Wire {
    Frame(Vec<u8>),
    OversizeLengthOnly,
}
fn fixture(
    prepare: impl FnOnce(&Path),
    transform: impl FnOnce(Reply<CasResponse>) -> Wire + Send + 'static,
) -> enclave_core::EnclaveResult<crate::ctl::OutboxDiagnosticsExport> {
    let directory = Directory::new();
    let env = crate::ctl::Env::dev(&directory.0, Profile::L1);
    let service = CasService::start(CasConfig {
        dev_same_uid: true,
        profile: Profile::L1,
        store_dir: directory.0.join("store"),
        audit_path: None,
        tuf_root: None,
        ohttp_gateway: None,
        state_dir: None,
        revocation: enclave_swarm_syncd::revocation::Enforcement::Unavailable,
    })
    .unwrap();
    prepare(&directory.0.join("store/ohttp-outbox"));
    let listener = ipc::bind(
        &env.socket_dir.join(DaemonId::SwarmSync.socket_name()),
        ipc::SocketAccess::OwnerOnly,
    )
    .unwrap();
    listener.set_nonblocking(true).unwrap();
    let worker = OwnedWorker(Some(thread::spawn(move || {
        let until = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < until,
                        "actual CLI acquisition did not connect"
                    );
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("owned listener failed: {error}"),
            }
        };
        // Explicitly restore blocking mode for Darwin accepted-socket inheritance.
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        let peer = ipc::PeerPolicy::allow([ipc::geteuid()])
            .check(&ipc::peer_credentials(&stream).unwrap())
            .unwrap();
        assert_eq!(
            peer.pid.and_then(|pid| u32::try_from(pid).ok()),
            Some(std::process::id())
        );
        let request: CasRequest = ipc::from_cbor(&ipc::read_frame(&mut stream).unwrap()).unwrap();
        assert!(matches!(request, CasRequest::OutboxDiagnostics));
        let response = match service.handle(&peer, request) {
            Ok(reply) => Reply::Ok(reply),
            Err(error) => Reply::Err(error),
        };
        match transform(response) {
            Wire::Frame(bytes) => ipc::write_frame(&mut stream, &bytes).unwrap(),
            Wire::OversizeLengthOnly => stream
                .write_all(&u32::try_from(ipc::MAX_FRAME + 1).unwrap().to_be_bytes())
                .unwrap(),
        }
    })));
    let result = crate::ctl::outbox_diagnostics(&env);
    worker.join(); // Every server is joined before consumer assertions.
    result
}
fn actual(
    prepare: impl FnOnce(&Path),
) -> enclave_core::EnclaveResult<crate::ctl::OutboxDiagnosticsExport> {
    fixture(prepare, |response| {
        let bytes = ipc::to_cbor(&response).unwrap();
        assert!(bytes.len() < 4096 && bytes.len() < ipc::MAX_FRAME);
        println!("OUTBOX_HEALTH_ACTUAL_FRAME_BYTES={}", bytes.len());
        Wire::Frame(bytes)
    })
}
fn mutated(
    transform: impl FnOnce(&mut Value) + Send + 'static,
) -> enclave_core::EnclaveResult<crate::ctl::OutboxDiagnosticsExport> {
    fixture(
        |_| {},
        move |response| {
            let mut value = serde_json::to_value(response).unwrap();
            let control = ipc::to_cbor(&WireValue(&value)).unwrap();
            let decoded: Reply<CasResponse> =
                ipc::from_cbor(&control).expect("healthy mutation adapter control");
            assert_eq!(serde_json::to_value(decoded).unwrap(), value);
            transform(&mut value["Ok"]["OutboxDiagnostics"]);
            Wire::Frame(ipc::to_cbor(&WireValue(&value)).unwrap())
        },
    )
}
fn assert_unknown(result: enclave_core::EnclaveResult<crate::ctl::OutboxDiagnosticsExport>) {
    let health = observed_outbox_health(result);
    assert!(!health.known && !health.healthy);
    assert_eq!(health.budget_exceeded, None);
    for field in [
        "queued_frames",
        "dead_frames",
        "disk_bytes",
        "budget_exceeded",
    ] {
        assert!(
            health.value[field].is_null(),
            "unknown {field} became a value"
        );
    }
    assert!(!health.value.to_string().contains(CANARY));
}

#[test]
fn outbox_health_real_cli_acquisition_distinguishes_safe_empty_missing_and_known_logical_quota() {
    let empty_export = actual(|_| {}).unwrap();
    assert_eq!(empty_export.peer_pid, std::process::id());
    assert_eq!(empty_export.peer_uid, ipc::geteuid());
    assert!(!empty_export.server_code_verified && empty_export.peer_code_identity.is_none());
    let empty = observed_outbox_health(Ok(empty_export));
    assert!(empty.known && empty.healthy);
    assert_eq!(empty.budget_exceeded, Some(false));
    assert_eq!(empty.value["queued_frames"], 0);
    assert_eq!(empty.value["dead_frames"], 0);
    assert_eq!(empty.value["disk_bytes"], 0);
    assert!(empty.value["path"].is_null());
    // Independent positive mixed inventory: a constant-zero queued_frames
    // adapter cannot pass these actual service/socket/CLI observations.
    let mixed = observed_outbox_health(actual(|queue| {
        use std::os::unix::fs::OpenOptionsExt;
        for (name, length) in [
            ("00000000000000000001.ohttp", 7_u64),
            ("00000000000000000002.dead", 11_u64),
            ("00000000000000000003.ohttp", 0_u64),
        ] {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(queue.join(name))
                .unwrap()
                .set_len(length)
                .unwrap();
        }
    }));
    assert!(mixed.known && mixed.healthy);
    assert_eq!(mixed.budget_exceeded, Some(false));
    assert_eq!(mixed.value["queued_frames"], 2);
    assert_eq!(mixed.value["dead_frames"], 1);
    assert_eq!(mixed.value["disk_bytes"], 18);
    let unknown = actual(|queue| std::fs::remove_dir(queue).unwrap()).unwrap();
    assert!(matches!(
        unknown.snapshot.observation,
        enclave_swarm_syncd::outbox::OutboxObservation::Unavailable {
            fault: enclave_swarm_syncd::outbox::OutboxObservationFault::Unavailable
        }
    ));
    assert_unknown(Ok(unknown));
    for extra in [0, 1_u64] {
        let health = observed_outbox_health(actual(move |queue| {
            use std::os::unix::fs::OpenOptionsExt;
            // Actual demand-zero logical file length, no payload-content writes.
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(queue.join("00000000000000000001.dead"))
                .unwrap()
                .set_len(100 * 1024 * 1024 + extra)
                .unwrap();
        }));
        assert!(health.known);
        assert_eq!(health.healthy, extra == 0);
        assert_eq!(health.budget_exceeded, Some(extra != 0));
        assert_eq!(health.value["queued_frames"], 0);
        assert_eq!(health.value["dead_frames"], 1);
        assert_eq!(health.value["disk_bytes"], 100 * 1024 * 1024 + extra);
    }
}

#[test]
fn outbox_health_real_cli_refuses_hostile_identity_schema_counts_and_unknown_wire_fields() {
    // A no-op mutation must work before any hostile refusal is accepted.
    assert!(observed_outbox_health(mutated(|_| {})).healthy);
    for field in 0..14 {
        let result = mutated(move |value| match field {
            0 => value["process_uid"] = json!(ipc::geteuid() ^ 1),
            1 => value["process_pid"] = json!(std::process::id() ^ 1),
            2 => value["dev_same_uid"] = json!(false),
            3 => value["producer"] = json!(CANARY),
            4 => value["schema"] = json!(2),
            5 => value["process_epoch_id"] = json!(CANARY),
            6 => value["process_pid"] = json!(0),
            7 => value["process_pid"] = json!(-1),
            8 => {
                value.as_object_mut().unwrap().remove("process_pid");
            }
            9 => value["observation"]["counts"]["pending_frames"] = json!(65_537),
            10 => value["observation"]["counts"]["retained_bytes"] = json!(1),
            11 => value["private_path"] = json!(CANARY),
            12 => {
                value["observation"] = json!({"availability":"unavailable", "fault":"namespace_busy", "counts":{
                "pending_frames":0,"dead_frames":0,"retained_bytes":0}})
            }
            _ => value["observation"]["counts"]["unrecognized_counter"] = json!(1),
        });
        let reason = match field {
            0..=2 => "OUTBOX_DIAGNOSTICS_IDENTITY",
            3..=6 | 9..=10 => "OUTBOX_DIAGNOSTICS_METADATA",
            _ => "OUTBOX_DIAGNOSTICS_ACQUIRE",
        };
        assert!(
            result.as_ref().is_err_and(|error| error.reason == reason),
            "field {field}: {result:?}"
        );
        assert_unknown(result);
    }
}

#[test]
fn outbox_health_real_cli_wrong_variant_private_backend_error_and_oversized_frame_remain_unknown() {
    let wrong = fixture(
        |_| {},
        |_| Wire::Frame(ipc::to_cbor(&Reply::Ok(CasResponse::Wiped)).unwrap()),
    );
    assert!(wrong
        .as_ref()
        .is_err_and(|error| error.reason == "OUTBOX_DIAGNOSTICS_RESPONSE"));
    assert_unknown(wrong);
    let error = fixture(
        |_| {},
        |_| {
            Wire::Frame(
                ipc::to_cbor(&Reply::<CasResponse>::Err(
                    enclave_core::error::EnclaveError::with(
                        enclave_core::error::Errno::EIO,
                        CANARY,
                        CANARY,
                    ),
                ))
                .unwrap(),
            )
        },
    );
    assert!(error
        .as_ref()
        .is_err_and(|error| error.reason == "OUTBOX_DIAGNOSTICS_ACQUIRE"));
    assert_unknown(error);
    let oversized = fixture(|_| {}, |_| Wire::OversizeLengthOnly);
    assert!(oversized
        .as_ref()
        .is_err_and(|error| error.reason == "OUTBOX_DIAGNOSTICS_ACQUIRE"));
    assert_unknown(oversized);
    // Actual absent owned endpoint; no filesystem scan or fixed host mutation.
    let directory = Directory::new();
    let env = crate::ctl::Env::dev(&directory.0, Profile::L1);
    let absent = crate::ctl::outbox_diagnostics(&env);
    assert!(absent
        .as_ref()
        .is_err_and(|error| error.reason == "OUTBOX_DIAGNOSTICS_CONNECT"));
    assert_unknown(absent);
}
