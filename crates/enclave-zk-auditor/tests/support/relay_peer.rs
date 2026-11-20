//! Same-UID, one-shot UDS peers for tests of the concrete relay boundary.
//! Receipt observation runs after a whole request is decoded and before Queued.
//! This fixture supplies no installed daemon or hardware identity authority.
use enclave_core::err;
use enclave_core::error::EnclaveResult;
use enclave_core::ipc::{self, Client, PreparedCall, Reply};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Serialize)]
enum RelayRequest<'a> {
    RelayRollup { frame: &'a serde_bytes::Bytes },
}

#[derive(Deserialize)]
enum ReceivedRelay {
    RelayRollup { frame: serde_bytes::ByteBuf },
}

#[derive(Serialize)]
enum RelayResponse {
    Queued,
}

#[allow(dead_code)]
pub enum ReplyAction {
    Queued,
    Close,
}

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn prepare_queued(
    frame: &[u8],
    received: impl FnOnce(Vec<u8>) + Send + 'static,
) -> EnclaveResult<PreparedCall> {
    prepare_with_reply(frame, move |bytes| {
        received(bytes);
        ReplyAction::Queued
    })
}

#[allow(dead_code)]
pub fn prepare_with_reply(
    frame: &[u8],
    received: impl FnOnce(Vec<u8>) -> ReplyAction + Send + 'static,
) -> EnclaveResult<PreparedCall> {
    // Keep Darwin's sockaddr_un path short. This is one private owned temporary
    // fixture, never another checkout or an installed daemon socket directory.
    let directory = Directory(
        std::env::temp_dir()
            .canonicalize()
            .map_err(|_| err!(EIO, "TEST_RELAY_TEMP"))?
            .join(format!("qr-{:x}", enclave_core::rng::u64())),
    );
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory.0)
        .map_err(|_| err!(EIO, "TEST_RELAY_DIRECTORY"))?;
    let path = directory.0.join("s");
    let listener = UnixListener::bind(&path).map_err(|_| err!(EIO, "TEST_RELAY_BIND"))?;
    listener
        .set_nonblocking(true)
        .map_err(|_| err!(EIO, "TEST_RELAY_NONBLOCK"))?;
    std::thread::spawn(move || {
        let _directory = directory;
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(_) => return,
            }
        };
        if stream.set_nonblocking(false).is_err() {
            return;
        }
        // The cooperating client writes one request with its absolute two-second
        // deadline. These timeouts also bound cancellation/abandoned fixtures.
        if stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .is_err()
            || stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .is_err()
        {
            return;
        }
        let bytes = match ipc::read_frame(&mut stream) {
            Ok(bytes) => bytes,
            Err(_) => return,
        };
        let ReceivedRelay::RelayRollup { frame } = match ipc::from_cbor(&bytes) {
            Ok(request) => request,
            Err(_) => return,
        };
        if matches!(received(frame.into_vec()), ReplyAction::Queued) {
            if let Ok(bytes) = ipc::to_cbor(&Reply::Ok(RelayResponse::Queued)) {
                let _ = ipc::write_frame(&mut stream, &bytes);
            }
        }
    });
    Client::connect_verified_deadline(&path, ipc::geteuid(), None, Duration::from_secs(2))?
        .prepare_call(&RelayRequest::RelayRollup {
            frame: serde_bytes::Bytes::new(frame),
        })
}
