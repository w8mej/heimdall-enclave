//! Tests for execution tickets and post-call row truncation (GAP-04, GAP-09).

use ed25519_dalek::{SigningKey, VerifyingKey};
use enclave_tool_host::TicketReplayFilter;
fn make_host(key: VerifyingKey) -> (tempfile::TempDir, ToolHost) {
    let dir = tempfile::Builder::new()
        .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .tempdir()
        .unwrap();
    let replay = TicketReplayFilter::initialize(
        &dir.path().canonicalize().unwrap().join("replay.redb"),
        4096,
    )
    .unwrap();
    (dir, ToolHost::new(key, replay))
}
use enclave_tool_host::host::{truncate_rows, truncate_rows_as, ToolHost};
use enclave_tool_host::ticket::{ExecutionTicket, RowFormat};
use rand_core::OsRng;

#[test]
fn ticket_lifecycle_and_replay_protection() {
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let (_directory, host) = make_host(verifying_key);

    let ticket_id = "ticket-001".to_string();
    let server = "filesystem".to_string();
    let tool_name = "list_directory".to_string();
    let args_jcs = br#"{"path":"/var/log"}"#;
    let args_blake3 = hex::encode(blake3::hash(args_jcs).as_bytes());
    let now = 1_000_000_000u64;
    let ttl = 5_000_000_000u64;

    let ticket = ExecutionTicket::issue(
        &signing_key,
        ticket_id.clone(),
        server.clone(),
        tool_name.clone(),
        args_blake3.clone(),
        2, // max 2 rows
        now,
        ttl,
    );

    // First execution succeeds and truncates
    let output = host
        .execute(
            &ticket,
            "filesystem",
            "list_directory",
            args_jcs,
            now + 100,
            |_srv, _tool, _args| {
                Ok(br#"["file1.txt","file2.txt","file3.txt","file4.txt"]"#.to_vec())
            },
        )
        .expect("first execution should succeed");

    assert!(output.truncated);
    assert_eq!(output.original_rows, Some(4));
    assert_eq!(output.final_rows, Some(2));
    assert_eq!(output.bytes, br#"["file1.txt","file2.txt"]"#);

    // Replay of same ticket fails closed
    let replay_err = host
        .execute(
            &ticket,
            "filesystem",
            "list_directory",
            args_jcs,
            now + 200,
            |_srv, _tool, _args| Ok(b"[]".to_vec()),
        )
        .unwrap_err();
    assert!(replay_err.is("TICKET_REPLAYED"));
}

#[test]
fn ticket_expired_fails_closed() {
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let (_directory, host) = make_host(verifying_key);

    let args_jcs = b"{}";
    let args_blake3 = hex::encode(blake3::hash(args_jcs).as_bytes());
    let now = 1_000_000_000u64;
    let ttl = 100_000_000u64; // 100ms

    let ticket = ExecutionTicket::issue(
        &signing_key,
        "ticket-exp".into(),
        "mock".into(),
        "tool".into(),
        args_blake3,
        10,
        now,
        ttl,
    );

    let err = host
        .execute(
            &ticket,
            "mock",
            "tool",
            args_jcs,
            now + ttl + 1,
            |_srv, _tool, _args| Ok(b"[]".to_vec()),
        )
        .unwrap_err();
    assert!(err.is("TICKET_EXPIRED"));
}

#[test]
fn ticket_args_mismatch_fails_closed() {
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let (_directory, host) = make_host(verifying_key);

    let args_jcs1 = b"{\"user\":\"alice\"}";
    let args_jcs2 = b"{\"user\":\"bob\"}";
    let args_blake3 = hex::encode(blake3::hash(args_jcs1).as_bytes());

    let ticket = ExecutionTicket::issue(
        &signing_key,
        "ticket-mismatch".into(),
        "mock".into(),
        "tool".into(),
        args_blake3,
        10,
        1000,
        5000,
    );

    let err = host
        .execute(
            &ticket,
            "mock",
            "tool",
            args_jcs2,
            1001,
            |_srv, _tool, _args| Ok(b"[]".to_vec()),
        )
        .unwrap_err();
    assert!(err.is("TICKET_ARGS_MISMATCH"));
}

#[test]
fn row_truncation_formats() {
    // JSON array truncation
    let json_input = br#"[{"id":1},{"id":2},{"id":3}]"#;
    let (out, trunc, orig, fin) = truncate_rows(json_input, 1).unwrap();
    assert!(trunc);
    assert_eq!(orig, Some(3));
    assert_eq!(fin, Some(1));
    assert_eq!(out, br#"[{"id":1}]"#);

    // Line-based text truncation
    let text_input = b"line1\nline2\nline3\nline4";
    let (out_txt, trunc_txt, orig_txt, fin_txt) =
        truncate_rows_as(text_input, 2, RowFormat::Utf8Lines).unwrap();
    assert!(trunc_txt);
    assert_eq!(orig_txt, Some(4));
    assert_eq!(fin_txt, Some(2));
    assert_eq!(out_txt, b"line1\nline2");

    // No truncation when within bounds
    let (out_no, trunc_no, _, _) = truncate_rows(json_input, 10).unwrap();
    assert!(!trunc_no);
    assert_eq!(out_no, json_input);
}

#[test]
fn dispatcher_target_must_match_ticket_before_any_side_effect() {
    let sk = SigningKey::from_bytes(&[4; 32]);
    let (_directory, host) = make_host(sk.verifying_key());
    let ticket = ExecutionTicket::issue(
        &sk,
        "target-test".into(),
        "a:b".into(),
        "c".into(),
        blake3::hash(b"{}").to_hex().to_string(),
        1,
        10,
        100,
    );
    for (server, tool) in [("other", "c"), ("a:b", "other"), ("a", "b:c")] {
        let err = host
            .execute(&ticket, server, tool, b"{}", 11, |_, _, _| {
                panic!("unauthorized dispatch")
            })
            .unwrap_err();
        assert!(err.is("TICKET_TOOL_MISMATCH"));
    }
    let out = host
        .execute(&ticket, "a:b", "c", b"{}", 11, |server, tool, args| {
            assert_eq!((server, tool, args), ("a:b", "c", b"{}".as_slice()));
            Ok(b"[]".to_vec())
        })
        .unwrap();
    assert_eq!(out.bytes, b"[]");
}

#[test]
fn row_contract_refuses_wrappers_binary_and_enforces_zero_and_cr_lines() {
    for bad in [br#"{"rows":[1,2,3]}"#.as_slice(), b"one line", b"\xff\x00"] {
        assert!(truncate_rows(bad, 1).is_err());
    }
    assert_eq!(truncate_rows(b"[1,2]", 0).unwrap().0, b"[]");
    assert_eq!(
        truncate_rows_as(b"a\rb\r\nc\n", 2, RowFormat::Utf8Lines).unwrap(),
        (b"a\nb".to_vec(), true, Some(3), Some(2))
    );
    assert_eq!(
        truncate_rows_as(b"a\nb", 0, RowFormat::Utf8Lines)
            .unwrap()
            .0,
        b""
    );
    assert!(truncate_rows_as(b"\xff", 1, RowFormat::Utf8Lines).is_err());
}
#[test]
fn host_uses_signed_output_contract() {
    let sk = SigningKey::from_bytes(&[4; 32]);
    let (_directory, host) = make_host(sk.verifying_key());
    let t = ExecutionTicket::issue(
        &sk,
        "format".into(),
        "s".into(),
        "t".into(),
        blake3::hash(b"{}").to_hex().to_string(),
        1,
        10,
        100,
    );
    assert!(host
        .execute(&t, "s", "t", b"{}", 11, |_, _, _| Ok(
            br#"{"rows":[1,2]}"#.to_vec()
        ))
        .unwrap_err()
        .is("TOOL_OUTPUT_ARRAY_REQUIRED"));
    let mut t = t.with_row_format(&sk, RowFormat::Utf8Lines);
    t.ticket_id = "text".into();
    // Reissue instead of mutating the signed identifier.
    let t = ExecutionTicket::issue(
        &sk,
        t.ticket_id,
        "s".into(),
        "t".into(),
        blake3::hash(b"{}").to_hex().to_string(),
        1,
        10,
        100,
    )
    .with_row_format(&sk, RowFormat::Utf8Lines);
    assert_eq!(
        host.execute(&t, "s", "t", b"{}", 11, |_, _, _| Ok(b"a\rb\rc".to_vec()))
            .unwrap()
            .bytes,
        b"a"
    );
    let mut altered = t.clone();
    altered.row_format = RowFormat::JsonArray;
    assert!(altered
        .verify(&sk.verifying_key(), 11, "s", "t", &t.args_blake3)
        .unwrap_err()
        .is("TICKET_SIG_VERIFY_FAILED"));
}
