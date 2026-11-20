//! CAS admission/restart custody regression. Real service and OHTTP bytes;
//! software-authority accounting proofs and same-UID peers confer no installed authority.
use std::{path::PathBuf, sync::{Arc, Mutex}};
use enclave_core::{ipc::PeerCredentials, profile::Profile};
use enclave_crypto::{ohttp::{bhttp_parse, decapsulate, gateway_keypair}, tuf::RepoBuilder};
use enclave_swarm_syncd::{
    outbox::{measure_outbox_disk, DrainStatus, HostConditions, OutboxDrainer, OutboxTransport},
    service::{CasConfig, CasRequest, CasResponse, CasService, L3_FRAME, LEDGER_PATH},
};

const NOW: i64 = 1_793_884_860;
#[path = "support/rollup_authority.rs"]
mod rollup_authority;
fn wall() -> i64 { NOW }
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}
#[derive(Default)]
struct RecordingTransport(Mutex<Vec<Vec<u8>>>);
impl OutboxTransport for RecordingTransport {
    fn transmit(&self, bytes: &[u8]) -> enclave_core::EnclaveResult<()> {
        self.0.lock().unwrap().push(bytes.to_vec());
        Ok(())
    }
}

#[test]
fn outbox_relay_clean_restart_preserves_pending_ciphertext_and_fifo() {
    restart(Profile::L3);
}

#[test]
fn l2_outbox_relay_clean_restart_preserves_pending_ciphertext_and_fifo() {
    restart(Profile::L2);
}

fn restart(profile: Profile) {
    use std::os::unix::fs::DirBuilderExt;
    // Match the existing required-TUF-state fixture: canonical temporary
    // ancestry is trusted; a group-writable repository mount need not be.
    let base = std::env::temp_dir().canonicalize().unwrap();
    let directory = Directory(base.join(format!(
        "outbox-restart-{}-{:x}", std::process::id(), enclave_core::rng::u64())));
    std::fs::DirBuilder::new().mode(0o700).create(&directory.0).unwrap();
    let repository = RepoBuilder::new(3, 2);
    let root = repository.root("2030-01-01T00:00:00Z").unwrap();
    let (gateway, secret) = gateway_keypair(3);
    let config = CasConfig {
        dev_same_uid: true, profile,
        store_dir: directory.0.join("store"), audit_path: Some(directory.0.join("cas.jsonl")),
        tuf_root: Some(root), ohttp_gateway: Some(gateway),
        state_dir: Some(directory.0.join("state")),
        revocation: enclave_swarm_syncd::revocation::Enforcement::InProcess,
    };
    let peer = PeerCredentials::local(enclave_core::ipc::geteuid(), 0);
    let outbox = config.store_dir.join("ohttp-outbox");
    let service = CasService::start_with_wall_clock(config.clone(), wall).unwrap();
    let authority = rollup_authority::Authority::new(profile);
    authority.install(&service, &config.store_dir, &repository, &peer);
    let first_frame = authority.frame(0x11);
    let second_frame = authority.frame(0x22);
    if profile == Profile::L3 {
        assert_eq!(first_frame.len(), L3_FRAME);
        assert_eq!(second_frame.len(), L3_FRAME);
    }
    assert!(matches!(service.handle(&peer, CasRequest::RelayRollup {
        frame: first_frame.clone().into(),
    }).unwrap(), CasResponse::Queued));
    let (_, before) = measure_outbox_disk(&outbox).unwrap();
    assert_eq!(before.len(), 1, "first genuine admission must leave one pending file");
    let old_path = before[0].clone();
    let old_bytes = std::fs::read(&old_path).unwrap();
    let (path, body) = bhttp_parse(&decapsulate(3, &secret, &old_bytes).unwrap()).unwrap();
    assert_eq!(path, LEDGER_PATH);
    assert_eq!(body, first_frame);
    let old_id = old_path.file_stem().unwrap().to_str().unwrap().parse::<u64>().unwrap();
    let seed = std::fs::read(config.state_dir.as_ref().unwrap().join("sealing.key")).unwrap();
    assert_eq!(seed.len(), 32);
    assert!(config.state_dir.as_ref().unwrap().join("tuf.sealed").is_file());
    assert!(config.state_dir.as_ref().unwrap().join("tuf.gen").is_file());
    assert_eq!(Arc::strong_count(&service), 1);
    drop(service); // Release the actual singleton and old State before restart.
    let service = CasService::start_with_wall_clock(config.clone(), wall).unwrap();
    assert!(std::fs::read(config.state_dir.as_ref().unwrap().join("sealing.key")).unwrap() == seed,
        "authority seed changed across restart");
    assert_eq!(std::fs::read(&old_path).unwrap(), old_bytes, "startup alone must preserve custody");
    assert!(matches!(service.handle(&peer, CasRequest::RelayRollup {
        frame: second_frame.clone().into(),
    }).unwrap(), CasResponse::Queued));
    let (_, pending) = measure_outbox_disk(&outbox).unwrap();
    let old_preserved = std::fs::read(&old_path).ok().as_deref() == Some(old_bytes.as_slice());
    let ids: Vec<u64> = pending.iter().map(|p|
        p.file_stem().unwrap().to_str().unwrap().parse().unwrap()).collect();
    let increasing_after_old = ids.len() == 2 && ids[0] == old_id && ids[0] < ids[1];
    let ciphertexts: Vec<Vec<u8>> = pending.iter().map(|p| std::fs::read(p).unwrap()).collect();
    let decoded: Vec<(usize, u8, bool)> = ciphertexts.iter().map(|bytes| {
        let (path, body) = bhttp_parse(&decapsulate(3, &secret, bytes).unwrap()).unwrap();
        assert_eq!(path, LEDGER_PATH);
        let marker = if body == first_frame {0x11} else if body == second_frame {0x22} else {0};
        (body.len(), marker, marker != 0)
    }).collect();
    let transport = Arc::new(RecordingTransport::default());
    let drainer = OutboxDrainer::new(&outbox, transport.clone());
    let report = drainer.drain_once(&HostConditions {
        ac_power: true, low_power: false, ..Default::default()
    }).unwrap();
    let sent_in_measured_fifo = *transport.0.lock().unwrap() == ciphertexts;
    assert_eq!(report.status, DrainStatus::Success);
    assert!(measure_outbox_disk(&outbox).unwrap().1.is_empty());
    // One terminal red compares all custody observations after the second real
    // admission AND actual drainer pass. It prints bounded marker summaries,
    // not 320-KiB proof-shaped buffers. No retry or crash test follows it.
    assert_eq!((pending.len(), old_preserved, increasing_after_old, decoded,
        report.frames_drained, report.frames_remaining, sent_in_measured_fifo),
        (2, true, true, vec![(first_frame.len(), 0x11, true), (second_frame.len(), 0x22, true)], 2, 0, true),
        "clean CAS restart must preserve old pending bytes, allocate a higher numeric ID and drain both in FIFO order");
    drop(service);
}
