//! Ordinary actual pipe/FD and public JSON tests; no native owner is fabricated.
use super::*;
use serde_json::{json, Value};
use std::{io::Write, thread};
fn pipe(nonblocking: bool) -> (File, File) {
    let mut fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    for fd in fds {
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
            0
        );
        if nonblocking {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            assert_eq!(
                unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
                0
            );
        }
    }
    unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) }
}
fn fixture_streams() -> (NativeStreams, File, File) {
    let (input, writer) = pipe(true);
    let (reader, output) = pipe(true);
    (
        NativeStreams {
            input: Stream::new(input, true).unwrap(),
            output: Stream::new(output, false).unwrap(),
        },
        writer,
        reader,
    )
}
#[test]
fn actual_pipe_partial_command_reads_complete_once_and_stdout_frame_preserves_json() {
    use std::io::Read;
    let (streams, mut writer, mut reader) = fixture_streams();
    let worker = thread::spawn(move || {
        writer.write_all(b"{\"version\":1,").unwrap();
        thread::sleep(Duration::from_millis(20));
        writer
            .write_all(b"\"op\":\"continue\",\"input_manifest\":\"/public/pickup.json\"}\n")
            .unwrap();
    });
    let parsed = streams
        .command(Instant::now() + Duration::from_secs(2))
        .unwrap();
    match parsed {
        SetupCommand::Continue {
            version,
            input_manifest,
        } => {
            assert_eq!(version, 1);
            assert_eq!(input_manifest, Path::new("/public/pickup.json"));
        }
        _ => panic!("continue required"),
    }
    worker.join().unwrap();
    let frame = json!({"version":1,"state":"public-fixture"});
    streams
        .frame(&frame, Instant::now() + Duration::from_secs(2))
        .unwrap();
    let mut bytes = [0; 256];
    let count = reader.read(&mut bytes).unwrap();
    assert_eq!(bytes[count - 1], b'\n');
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes[..count - 1]).unwrap(),
        frame
    );
}
#[test]
fn actual_pipe_eof_extra_command_and_oversized_data_refuse() {
    let (streams, writer, _) = fixture_streams();
    drop(writer);
    assert!(streams
        .command(Instant::now() + Duration::from_secs(1))
        .err()
        .unwrap()
        .is("BIRTH_SESSION_INPUT_EOF"));
    for payload in [
        b"{\"version\":1,\"op\":\"cancel\"}\n{}\n".to_vec(),
        vec![b'x'; MAX_COMMAND + 1],
    ] {
        let (streams, mut writer, _) = fixture_streams();
        let sender = thread::spawn(move || {
            let mut offset = 0;
            while offset < payload.len() {
                match writer.write(&payload[offset..]) {
                    Ok(count) => offset += count,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::yield_now()
                    }
                    Err(_) => break,
                }
            }
        });
        let error = streams
            .command(Instant::now() + Duration::from_secs(2))
            .err()
            .unwrap();
        assert!(
            error.is("BIRTH_SESSION_ONE_COMMAND_REQUIRED") || error.is("BIRTH_SESSION_INPUT_BOUND")
        );
        drop(streams);
        sender.join().unwrap();
    }
}
#[test]
fn full_output_and_empty_input_hit_original_deadline_without_blocking_or_flag_changes() {
    let (streams, _writer, _reader) = fixture_streams();
    let error = streams
        .command(Instant::now() + Duration::from_millis(20))
        .err()
        .unwrap();
    assert!(error.is("BIRTH_SESSION_IO_TIMEOUT"));
    let bytes = [b'x'; 4096];
    loop {
        let count = unsafe {
            libc::write(
                streams.output.file.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
            )
        };
        if count < 0 {
            assert_eq!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock
            );
            break;
        }
    }
    let before = unsafe { libc::fcntl(streams.output.file.as_raw_fd(), libc::F_GETFL) };
    assert!(streams
        .frame(
            &json!({"version":1}),
            Instant::now() + Duration::from_millis(20)
        )
        .err()
        .unwrap()
        .is("BIRTH_SESSION_IO_TIMEOUT"));
    assert_eq!(before, unsafe {
        libc::fcntl(streams.output.file.as_raw_fd(), libc::F_GETFL)
    });
    let (input, _) = pipe(false);
    let raw = input.as_raw_fd();
    let duplicate = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 3) };
    assert!(duplicate >= 0);
    let before = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    assert!(Stream::new(unsafe { File::from_raw_fd(duplicate) }, true)
        .err()
        .unwrap()
        .is("BIRTH_SESSION_NONBLOCKING_PIPE_STREAMS_REQUIRED"));
    assert_eq!(before, unsafe { libc::fcntl(raw, libc::F_GETFL) });
}
fn pickup() -> Value {
    let roles = [
        "inventory",
        "custody_manifest",
        "custody_policy",
        "policy_issuer_key",
        "inventory_issuer_key",
        "envelope_issuer_key",
        "staged_pins",
    ];
    json!({"version":1,"kind":"mcpmac-dedicated-birth-public-inputs","target_id":"ykft-public-test","descriptor_sha256":"ab".repeat(32),
        "package_root":"/public/package","initial_sources":roles.into_iter().enumerate().map(|(index,role)|json!({"role":role,
            "path":format!("/public/package/initial/{index}"),"sha256":"cd".repeat(32),"size":17})).collect::<Vec<_>>(),
        "remaining_staged_sources":[{"relative":"bin/mcp-enclave","path":"/public/package/stage/bin/mcp-enclave","sha256":"ef".repeat(32),"size":31}],
        "software_release_config":"/public/software/config.json","operator_runtime_pin_record":"/public/runtime/record.json"})
}
#[test]
fn public_pickup_scopes_and_role_transport_are_exact_without_authority() {
    let value = pickup();
    let parsed = Pickup::parse(
        &serde_json::to_vec(&value).unwrap(),
        "ykft-public-test",
        &"ab".repeat(32),
        Path::new("/allocated/nonce"),
    )
    .unwrap();
    assert_eq!(parsed.initial().len(), 7);
    assert_eq!(parsed.staged().len(), 1);
    for slot in 0..7 {
        let mut changed = value.clone();
        match slot {
            0 => changed["target_id"] = "old-target".into(),
            1 => changed["descriptor_sha256"] = "00".repeat(32).into(),
            2 => changed["initial_sources"][1]["role"] = "inventory".into(),
            3 => changed["remaining_staged_sources"][0]["relative"] = "codesign-pins.json".into(),
            4 => changed["package_root"] = "/allocated/nonce/package".into(),
            5 => changed["remaining_staged_sources"][0]["path"] = "/public/outside".into(),
            _ => changed["secret"] = "REFUSED-UNKNOWN-FIELD".into(),
        }
        assert!(Pickup::parse(
            &serde_json::to_vec(&changed).unwrap(),
            "ykft-public-test",
            &"ab".repeat(32),
            Path::new("/allocated/nonce")
        )
        .is_err());
    }
}
#[test]
fn command_schema_refuses_duplicate_unknown_escaped_version_and_secret_fields() {
    for bytes in [
        br#"{"version":1,"version":1,"op":"cancel"}"#.as_slice(),
        br#"{"version":1,"op":"cancel","pin":"never-accepted"}"#,
        br#"{"version":2,"op":"cancel"}"#,
        br#"{"version":1,"op":"continue","input_manifest":"/public/\u0070ickup"}"#,
        br#"{"version":1,"op":"continue","input_manifest":"relative"}"#,
    ] {
        assert!(command(bytes).is_err());
    }
    assert!(matches!(
        command(br#"{"version":1,"op":"cancel"}"#).unwrap(),
        SetupCommand::Cancel { version: 1 }
    ));
}
