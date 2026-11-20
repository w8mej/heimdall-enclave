//! Actual signed-table issuer -> durable host -> native ABI regressions (F100).
use ed25519_dalek::SigningKey;
use enclave_tool_host::artifacts::{
    sign_manifest, ApprovedModuleV1, ArtifactDispatcher, ArtifactManifestV1,
    SignedArtifactManifestV1, TrustedArtifactTable,
};
use enclave_tool_host::lifecycle::trusted_unix_ns;
use enclave_tool_host::{ticket::RowFormat, DurableToolHost};
use std::os::unix::fs::PermissionsExt;

const WAT: &str = r#"(module
 (memory (export "memory") 1)
 (func (export "alloc") (param i32) (result i32) i32.const 0)
 (func (export "run") (param i32 i32) (result i32)
   local.get 0 i32.const 5 i32.add i32.load8_u))"#;

#[test]
fn manifest_signature_preserves_current_and_maximum_integer_nanoseconds() {
    use ed25519_dalek::Verifier;
    let key = SigningKey::from_bytes(&[81; 32]);
    for now in [trusted_unix_ns().unwrap(), u64::MAX - 1] {
        let manifest = ArtifactManifestV1 {
            v: 1,
            issued_at_unix_ns: now,
            expires_at_unix_ns: now + 1,
            modules: vec![],
        };
        let signed = sign_manifest(manifest, &key).unwrap();
        let round: SignedArtifactManifestV1 =
            serde_json::from_slice(&serde_json::to_vec(&signed).unwrap()).unwrap();
        assert_eq!(round.manifest.issued_at_unix_ns, now);
        let sig =
            ed25519_dalek::Signature::from_slice(&hex::decode(&signed.signature).unwrap()).unwrap();
        key.verifying_key()
            .verify(&round.manifest.signing_bytes().unwrap(), &sig)
            .unwrap();
        let mut changed = round.manifest;
        changed.issued_at_unix_ns -= 1;
        assert!(key
            .verifying_key()
            .verify(&changed.signing_bytes().unwrap(), &sig)
            .is_err());
    }
}
fn artifact(source: &str) -> Vec<u8> {
    let mut cfg = wasmtime::Config::new();
    cfg.consume_fuel(true).max_wasm_stack(512 * 1024);
    wasmtime::Module::new(&wasmtime::Engine::new(&cfg).unwrap(), source)
        .unwrap()
        .serialize()
        .unwrap()
}
struct Fixture {
    dir: tempfile::TempDir,
    signed: SignedArtifactManifestV1,
    build: SigningKey,
    issuer: SigningKey,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let bytes = artifact(WAT);
        std::fs::write(dir.path().join("a.cwasm"), &bytes).unwrap();
        let build = SigningKey::from_bytes(&[81; 32]);
        let issuer = SigningKey::from_bytes(&[82; 32]);
        let now = trusted_unix_ns().unwrap();
        let signed = sign_manifest(
            ArtifactManifestV1 {
                v: 1,
                issued_at_unix_ns: now,
                expires_at_unix_ns: now + 60_000_000_000,
                modules: vec![ApprovedModuleV1 {
                    server: "approved".into(),
                    tool_name: "a".into(),
                    file_name: "a.cwasm".into(),
                    module_blake3: *blake3::hash(&bytes).as_bytes(),
                    tools_list: serde_json::json!({"tools":[{"name":"a"}]}),
                    row_format: RowFormat::JsonArray,
                    max_rows: 1,
                }],
            },
            &build,
        )
        .unwrap();
        Self {
            dir,
            signed,
            build,
            issuer,
        }
    }
    fn table(&self) -> enclave_core::error::EnclaveResult<TrustedArtifactTable> {
        let mut table = TrustedArtifactTable::load(
            &serde_json::to_vec(&self.signed).unwrap(),
            &self.build.verifying_key(),
            &self.dir.path().canonicalize().unwrap(),
        )?;
        table.verify_tools_lists(|server, list| {
            if server != "approved" || list != &serde_json::json!({"tools":[{"name":"a"}]}) {
                return Err(enclave_core::err!(EACCES, "FIXTURE_TOOL_PIN"));
            }
            Ok(())
        })?;
        Ok(table)
    }
    fn replay(&self) -> std::path::PathBuf {
        self.dir.path().canonicalize().unwrap().join("replay")
    }
    fn provision(&self) {
        drop(DurableToolHost::provision(&self.replay(), self.issuer.verifying_key(), 32).unwrap());
    }
    fn dispatcher(&self) -> ArtifactDispatcher {
        ArtifactDispatcher::open(self.table().unwrap(), &self.replay(), self.issuer.clone())
            .unwrap()
    }
}

#[test]
fn actual_issuer_selects_approved_bytes_and_delivers_exact_args_across_restart() {
    let fixture = Fixture::new();
    fixture.provision();
    let dispatcher = fixture.dispatcher();
    let (out, list) = dispatcher
        .execute("approved", "a", br#"{"n":7}"#, 1, &[1; 32])
        .unwrap();
    assert_eq!(out.bytes, br#"[{"result":55}]"#);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&list).unwrap(),
        fixture.signed.manifest.modules[0].tools_list
    );
    assert!(dispatcher
        .execute("approved", "a", br#"{"n":7}"#, 1, &[1; 32])
        .unwrap_err()
        .is("TICKET_REPLAYED"));
    drop(dispatcher);
    let dispatcher = fixture.dispatcher();
    assert!(dispatcher
        .execute("approved", "a", br#"{"n":7}"#, 1, &[1; 32])
        .unwrap_err()
        .is("TICKET_REPLAYED"));
    assert_eq!(
        dispatcher
            .execute("approved", "a", br#"{"n":8}"#, 1, &[2; 32])
            .unwrap()
            .0
            .bytes,
        br#"[{"result":56}]"#
    );
}

#[test]
fn artifact_b_cannot_run_under_signed_target_a_and_loaded_snapshot_cannot_change() {
    let fixture = Fixture::new();
    fixture.provision();
    let dispatcher = fixture.dispatcher();
    let different = artifact("(module (memory (export \"memory\") 1))");
    std::fs::write(fixture.dir.path().join("a.cwasm"), &different).unwrap();
    assert!(fixture.table().unwrap_err().is("TOOL_ARTIFACT_DIGEST"));
    assert_eq!(
        dispatcher
            .execute("approved", "a", br#"{"n":7}"#, 1, &[3; 32])
            .unwrap()
            .0
            .bytes,
        br#"[{"result":55}]"#
    );
    assert!(dispatcher
        .execute("approved", "b", b"{}", 1, &[4; 32])
        .unwrap_err()
        .is("TOOL_ARTIFACT_NOT_APPROVED"));
}

#[test]
fn independent_build_key_signature_target_digest_and_metadata_are_mandatory() {
    let mut fixture = Fixture::new();
    let bytes = serde_json::to_vec(&fixture.signed).unwrap();
    assert!(TrustedArtifactTable::load(
        &bytes,
        &SigningKey::from_bytes(&[90; 32]).verifying_key(),
        &fixture.dir.path().canonicalize().unwrap()
    )
    .unwrap_err()
    .is("TOOL_MANIFEST_UNTRUSTED"));
    fixture.signed.manifest.modules[0].tool_name = "b".into();
    assert!(fixture.table().unwrap_err().is("TOOL_MANIFEST_UNTRUSTED"));
    fixture.signed.manifest.modules[0].module_blake3 = [9; 32];
    fixture.signed = sign_manifest(fixture.signed.manifest.clone(), &fixture.build).unwrap();
    assert!(fixture.table().unwrap_err().is("TOOL_ARTIFACT_DIGEST"));
    let fixture = Fixture::new();
    assert!(fixture
        .table()
        .unwrap()
        .verify_tools_lists(|_, _| Err(enclave_core::err!(EACCES, "PIN_MISMATCH")))
        .unwrap_err()
        .is("PIN_MISMATCH"));
}

#[test]
fn table_rejects_missing_links_traversal_duplicate_expired_and_absent_authority() {
    use std::os::unix::fs::symlink;
    let mut fixture = Fixture::new();
    let original = fixture.signed.clone();
    fixture.signed.manifest.modules[0].file_name = "../a.cwasm".into();
    fixture.signed = sign_manifest(fixture.signed.manifest.clone(), &fixture.build).unwrap();
    assert!(fixture.table().unwrap_err().is("TOOL_MANIFEST_TARGET"));
    fixture.signed = original.clone();
    fixture
        .signed
        .manifest
        .modules
        .push(fixture.signed.manifest.modules[0].clone());
    fixture.signed = sign_manifest(fixture.signed.manifest.clone(), &fixture.build).unwrap();
    assert!(fixture.table().unwrap_err().is("TOOL_MANIFEST_DUPLICATE"));
    fixture.signed = original.clone();
    fixture.signed.manifest.expires_at_unix_ns = 2;
    fixture.signed.manifest.issued_at_unix_ns = 1;
    fixture.signed = sign_manifest(fixture.signed.manifest.clone(), &fixture.build).unwrap();
    assert!(fixture
        .table()
        .unwrap_err()
        .is("TOOL_MANIFEST_TIME_OR_VERSION"));
    fixture.signed = original;
    std::fs::rename(
        fixture.dir.path().join("a.cwasm"),
        fixture.dir.path().join("real"),
    )
    .unwrap();
    assert!(fixture.table().is_err());
    symlink(
        fixture.dir.path().join("real"),
        fixture.dir.path().join("a.cwasm"),
    )
    .unwrap();
    assert!(fixture.table().is_err());
    assert!(TrustedArtifactTable::load(
        b"{}",
        &fixture.build.verifying_key(),
        &fixture.dir.path().canonicalize().unwrap()
    )
    .is_err());
}

#[test]
fn issuer_refuses_bad_args_row_limits_missing_state_and_native_failures() {
    let fixture = Fixture::new();
    assert!(ArtifactDispatcher::open(
        fixture.table().unwrap(),
        &fixture.replay(),
        fixture.issuer.clone()
    )
    .is_err());
    assert!(!fixture.replay().exists());
    fixture.provision();
    let dispatcher = fixture.dispatcher();
    assert!(dispatcher
        .execute("approved", "a", b"{ \"n\":7}", 1, &[5; 32])
        .unwrap_err()
        .is("TOOL_ARGUMENT_CANONICAL"));
    assert!(dispatcher
        .execute("approved", "a", b"{}", 2, &[5; 32])
        .unwrap_err()
        .is("TOOL_DISPATCH_LIMIT"));
    drop(dispatcher);
    for (source, expected) in [
        (
            "(module (memory (export \"memory\") 1))",
            "WASM_ALLOC_REQUIRED",
        ),
        (
            r#"(module (memory (export "memory") 1)
        (func (export "alloc") (param i32) (result i32) i32.const 0)
        (func (export "run") (param i32 i32) (result i32) (loop br 0) i32.const 0))"#,
            "WASM_CALL",
        ),
        (
            "(module (memory (export \"memory\") 2048))",
            "WASM_INSTANCE",
        ),
    ] {
        let mut fixture = Fixture::new();
        let bytes = artifact(source);
        std::fs::write(fixture.dir.path().join("a.cwasm"), &bytes).unwrap();
        fixture.signed.manifest.modules[0].module_blake3 = *blake3::hash(&bytes).as_bytes();
        fixture.signed = sign_manifest(fixture.signed.manifest.clone(), &fixture.build).unwrap();
        fixture.provision();
        assert!(fixture
            .dispatcher()
            .execute("approved", "a", b"{}", 1, &[6; 32])
            .unwrap_err()
            .is(expected));
    }
}

#[test]
fn private_argument_refusals_preserve_ticket_for_corrected_canonical_call() {
    let fixture = Fixture::new();
    fixture.provision();
    let dispatcher = fixture.dispatcher();
    let authorization = [91; 32];
    for (bytes, expected) in [
        (b"{".as_slice(), "TOOL_ARGUMENT_JSON"),
        (br#"["private-value"]"#, "TOOL_ARGUMENT_CANONICAL"),
        (br#"{ "private-key" : "private-value" }"#, "TOOL_ARGUMENT_CANONICAL"),
        (br#"{"a":"private-prefix","z":9007199254740993}"#, "JCS_INTEGER_OUT_OF_RANGE"),
    ] {
        assert!(dispatcher.execute("approved", "a", bytes, 1, &authorization)
            .unwrap_err().is(expected));
    }
    // Every rejected argument shape precedes ticket issue/consumption. The same
    // authorization can still complete once; the ordinary replay guard remains.
    assert_eq!(dispatcher.execute("approved", "a", br#"{"n":7}"#, 1, &authorization)
        .unwrap().0.bytes, br#"[{"result":55}]"#);
    assert!(dispatcher.execute("approved", "a", br#"{"n":7}"#, 1, &authorization)
        .unwrap_err().is("TICKET_REPLAYED"));
}

#[cfg(feature = "offline-builder")]
#[test]
fn real_offline_builder_compiles_wasm_then_signs_and_refuses_native_input() {
    let fixture = Fixture::new();
    let root = fixture.dir.path().canonicalize().unwrap();
    std::fs::write(root.join("source.wat"), WAT).unwrap();
    std::fs::write(root.join("build-key"), hex::encode([81; 32])).unwrap();
    std::fs::set_permissions(
        root.join("build-key"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let recipe = serde_json::json!({"valid_for_seconds":60,"tools":[{"server":"approved","tool_name":"a",
        "source":root.join("source.wat"),"tools_list":{"tools":[{"name":"a"}]},"max_rows":1}]});
    std::fs::write(root.join("recipe"), serde_json::to_vec(&recipe).unwrap()).unwrap();
    let outdir = root.join("built");
    std::fs::create_dir(&outdir).unwrap();
    std::fs::set_permissions(&outdir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let run = |directory: &std::path::Path| {
        std::process::Command::new(env!("CARGO_BIN_EXE_enclave-tool-build"))
            .args([
                root.join("recipe"),
                root.join("build-key"),
                directory.to_path_buf(),
            ])
            .output()
            .unwrap()
    };
    let out = run(&outdir);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut table = TrustedArtifactTable::load(
        &std::fs::read(outdir.join("manifest.json")).unwrap(),
        &fixture.build.verifying_key(),
        &outdir,
    )
    .unwrap();
    table
        .verify_tools_lists(|server, list| {
            assert_eq!(server, "approved");
            assert_eq!(list, &serde_json::json!({"tools":[{"name":"a"}]}));
            Ok(())
        })
        .unwrap();
    fixture.provision();
    let dispatcher =
        ArtifactDispatcher::open(table, &fixture.replay(), fixture.issuer.clone()).unwrap();
    assert_eq!(
        dispatcher
            .execute("approved", "a", br#"{"n":7}"#, 1, &[7; 32])
            .unwrap()
            .0
            .bytes,
        br#"[{"result":55}]"#
    );
    std::fs::write(root.join("source.wat"), artifact(WAT)).unwrap();
    let rejected = root.join("rejected");
    std::fs::create_dir(&rejected).unwrap();
    std::fs::set_permissions(&rejected, std::fs::Permissions::from_mode(0o700)).unwrap();
    let negative = run(&rejected);
    assert!(
        !negative.status.success(),
        "offline signer must compile Wasm, never sign supplied native bytes"
    );
    assert!(String::from_utf8_lossy(&negative.stderr).contains("OFFLINE_WASM_INPUT"));
    assert_eq!(std::fs::read_dir(&rejected).unwrap().count(), 0);
}

#[test]
fn skipped_lock_verification_and_collapsed_signing_authorities_are_refused() {
    let fixture = Fixture::new();
    fixture.provision();
    let unverified = TrustedArtifactTable::load(
        &serde_json::to_vec(&fixture.signed).unwrap(),
        &fixture.build.verifying_key(),
        &fixture.dir.path().canonicalize().unwrap(),
    )
    .unwrap();
    assert!(
        ArtifactDispatcher::open(unverified, &fixture.replay(), fixture.issuer.clone())
            .unwrap_err()
            .is("TOOL_METADATA_NOT_VERIFIED")
    );
    assert!(ArtifactDispatcher::open(
        fixture.table().unwrap(),
        &fixture.replay(),
        fixture.build.clone()
    )
    .unwrap_err()
    .is("TOOL_BUILD_ISSUER_KEYS_NOT_DISTINCT"));
}
