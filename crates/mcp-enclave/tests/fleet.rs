//! Wave 6 end-to-end: the CLI starts all five daemons (dev, same-UID,
//! simulated hardware), every cross-daemon path runs over peer-checked UDS,
//! and the steady-state RSS budget (`UID 702–705 <= 152 MiB`, total
//! `<= 200 MiB`) and the zero-W+X rule hold.

mod common;

#[test]
fn f38_supervisor_argv_preserves_selected_monitor_security_profile() {
    for profile in ["L1", "L2", "L3"] {
        let layout = mcp_enclave::launchd::Layout { profile: profile.into(), ..Default::default() };
        let plist = mcp_enclave::launchd::supervisor_plist(&layout);
        assert!(plist.contains(&format!("<string>--profile</string>\n\t\t<string>{profile}</string>\n\t\t<string>supervise</string>")));
    }
}

use std::path::{Path, PathBuf};
use std::process::Command;

use enclave_core::daemon::{DaemonId, MIB};
use enclave_custody_vaultd::service::{VaultRequest, VaultResponse};
use enclave_zk_auditor::service::{ProveEpochRequest, ZkRequest, ZkResponse};

struct Fleet {
    state: PathBuf,
}

impl Fleet {
    fn cli(&self, args: &[&str]) -> std::process::Output {
        let mut c = Command::new(env!("CARGO_BIN_EXE_mcp-enclave"));
        c.args([
            "--dev",
            "--state-dir",
            self.state.to_str().unwrap(),
            "--profile",
            "L1",
            "--json",
        ])
        .args(args);
        if std::env::var_os("MCP_ENCLAVE_TEST_DEDICATED").is_none() {
            // Deterministic: run the daemon entry points embedded in this
            // freshly built CLI rather than possibly stale sibling binaries.
            c.env("MCP_ENCLAVE_EMBEDDED_DAEMONS", "1");
        }
        c.output().unwrap()
    }
    fn ok(&self, args: &[&str]) -> serde_json::Value {
        let o = self.cli(args);
        assert!(
            o.status.success(),
            "{args:?}: {}\n{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        serde_json::from_slice(&o.stdout).unwrap_or(serde_json::Value::Null)
    }
    fn env(&self) -> mcp_enclave::ctl::Env {
        mcp_enclave::ctl::Env::dev(&self.state, enclave_core::profile::Profile::L1)
    }
}

impl Drop for Fleet {
    fn drop(&mut self) {
        let _ = self.cli(&["daemon", "stop"]);
        let _ = std::fs::remove_dir_all(&self.state);
    }
}

fn tmp() -> PathBuf {
    // Short path: UNIX socket paths are limited to ~104 bytes on macOS.
    // Resolve /tmp first: on macOS it is a symlink to /private/tmp, and the
    // daemons refuse private state paths that traverse a symlink.
    let base = std::fs::canonicalize("/tmp").unwrap_or_else(|_| PathBuf::from("/tmp"));
    base.join(format!(
        "mcpe-{}-{:x}",
        std::process::id(),
        enclave_core::rng::u64() & 0xffff_ffff
    ))
}

fn check_budget(s: &serde_json::Value, phase: &str) {
    assert_eq!(s["healthy"], true, "{phase}: {s:#}");
    for r in s["rows"].as_array().unwrap() {
        let (rss, cap) = (
            r["rss_bytes"].as_u64().unwrap(),
            r["ceiling_bytes"].as_u64().unwrap(),
        );
        println!(
            "{phase}: uid {} {:<24} rss {:6.2} MiB / {} MiB",
            r["uid"],
            r["binary"].as_str().unwrap(),
            rss as f64 / MIB as f64,
            cap / MIB
        );
        assert!(
            rss > 0 && rss <= cap,
            "{phase}: uid {} over its ceiling",
            r["uid"]
        );
    }
    let sub = s["rss_702_705_bytes"].as_u64().unwrap();
    let tot = s["rss_total_bytes"].as_u64().unwrap();
    println!(
        "{phase}: UID 702–705 = {:.2} MiB (<= 152), total = {:.2} MiB (<= 200)",
        sub as f64 / MIB as f64,
        tot as f64 / MIB as f64
    );
    assert!(sub <= 152 * MIB && tot <= 200 * MIB);
    // GAP-14 (ADR-006): burst budget <= 232 MiB including the _enclaveintent helper (32 MiB ceiling).
    let burst_tot = tot + enclave_core::daemon::INTENT_HELPER_MIB * MIB;
    assert!(
        burst_tot <= enclave_core::daemon::ACTIVE_PROMPT_BUDGET_MIB * MIB,
        "{phase}: burst total with helper {:.2} MiB exceeded 232 MiB ceiling",
        burst_tot as f64 / MIB as f64
    );
}

fn journal_files(dir: &Path) -> Vec<PathBuf> {
    let mut v = mcp_enclave::ctl::journal_files(dir).unwrap();
    v.sort();
    v
}

#[test]
fn five_daemon_mesh_end_to_end() {
    let f = Fleet { state: tmp() };
    mcp_enclave::ctl::prepare_dev_state_at(&f.env(), &common::host_inputs(&f.state)).unwrap();
    let started = f.ok(&["daemon", "start"]);
    assert_eq!(started.as_array().unwrap().len(), 5);
    check_budget(&f.ok(&["daemon", "status"]), "idle");

    // Zero W+X mappings in every daemon (zero-JIT).
    for r in f.ok(&["daemon", "status"])["rows"].as_array().unwrap() {
        let pid = r["pid"].as_u64().unwrap() as u32;
        if let Some(n) = enclave_core::resource::writable_executable_mappings(pid) {
            assert_eq!(n, 0, "uid {} has W+X mappings", r["uid"]);
        }
    }

    // Client-side peer authentication: a socket owned by the wrong UID is refused.
    let e = enclave_core::ipc::Client::connect(
        &f.state
            .join("run")
            .join(DaemonId::CustodyVault.socket_name()),
        703,
    );
    if enclave_core::ipc::geteuid() != 703 {
        assert!(e.unwrap_err().is("SERVER_UID_MISMATCH"));
    }

    // TUF refresh is idempotent; a second bootstrap is refused (admin TOFU once).
    f.ok(&["tuf", "refresh"]);
    let o = f.cli(&["tuf", "refresh", "--bootstrap"]);
    assert!(
        !o.status.success()
            && String::from_utf8_lossy(&o.stderr).contains("TUF_ALREADY_BOOTSTRAPPED")
    );

    // Admit + bind one reference model per class; each bind replaces the last.
    for class in [
        "AR_CAUSAL",
        "DISCRETE_DIFFUSION",
        "RECURRENT_SSM_TTT",
        "BYTE_OR_CONCEPT",
        "SPECULATIVE_OR_RECURRENT_DEPTH",
        "JEPA_EBM_WORLD_PLANNER",
        "DISCRIMINATIVE_RLCD",
    ] {
        let a = f.ok(&["model", "admit", "--class", class]);
        assert_eq!(a["class"], class, "{a:#}");
        assert!(a["cas_uri"]
            .as_str()
            .unwrap()
            .starts_with("cas://blake3-bao-v1/"));
        let target = enclave_model_runnerd::service::model_manifest_target(
            a["model_id"].as_str().unwrap(),
        ).unwrap();
        let signed = enclave_core::host_config::fetch_tuf_target(
            &f.env().socket_dir, &target, true,
        ).unwrap();
        let mut manifest: serde_json::Value = serde_json::from_slice(&signed).unwrap();
        assert_eq!(manifest["artifact"]["cas_uri"], a["cas_uri"]);
        if class == "AR_CAUSAL" {
            // UID 701 must still refuse caller-modified security controls,
            // even though the same model's exact manifest is now published.
            manifest["max_provenance_fanin"] = serde_json::json!(63);
            let error = f.env().connect(DaemonId::ModelRunner).unwrap()
                .call::<_, RunnerResponse>(&RunnerRequest::Bind {
                    manifest: serde_json::to_vec(&manifest).unwrap().into(),
                    cas_uri: a["cas_uri"].as_str().unwrap().to_owned(),
                    calibration_corpus: None,
                }).unwrap_err();
            assert!(error.is("MODEL_MANIFEST_UNSIGNED"), "{error}");

            // A newly signed corpus target still cannot override the separate
            // digest already pinned by the signed host configuration.
            let corpus_target = enclave_core::host_config::CALIBRATION_CORPUS_TARGET;
            let corpus_path = f.state.join("cas").join(corpus_target);
            let original = std::fs::read(&corpus_path).unwrap();
            let replacement = b"independently signed but different calibration fixture";
            let mut repo = mcp_enclave::devtuf::DevRepo::open(&f.state.join("tuf")).unwrap();
            repo.add_target(corpus_target, replacement, serde_json::json!({})).unwrap();
            enclave_core::fsutil::write_private(&corpus_path, replacement).unwrap();
            mcp_enclave::ctl::tuf_refresh(&f.env(), &repo.repo_dir(), false).unwrap();
            let error = f.env().connect(DaemonId::ModelRunner).unwrap()
                .call::<_, RunnerResponse>(&RunnerRequest::Bind {
                    manifest: signed.into(),
                    cas_uri: a["cas_uri"].as_str().unwrap().to_owned(),
                    calibration_corpus: None,
                }).unwrap_err();
            assert!(error.is("CALIBRATION_CORPUS_DIGEST"), "{error}");
            repo.add_target(corpus_target, &original, serde_json::json!({})).unwrap();
            enclave_core::fsutil::write_private(&corpus_path, &original).unwrap();
            mcp_enclave::ctl::tuf_refresh(&f.env(), &repo.repo_dir(), false).unwrap();
        }
    }
    // A manifest whose signed class disagrees with --class is refused.
    let p = enclave_model_runnerd::zoo::package(
        enclave_model_runnerd::manifest::ExecutionClass::RecurrentSsmTtt,
    )
    .unwrap();
    std::fs::write(f.state.join("m.json"), p.manifest_bytes()).unwrap();
    std::fs::write(f.state.join("w.safetensors"), &p.weights).unwrap();
    let o = f.cli(&[
        "model",
        "admit",
        "--class",
        "AR_CAUSAL",
        "--manifest",
        f.state.join("m.json").to_str().unwrap(),
        "--weights",
        f.state.join("w.safetensors").to_str().unwrap(),
    ]);
    assert!(
        !o.status.success()
            && String::from_utf8_lossy(&o.stderr).contains("EXECUTION_CLASS_MISMATCH")
    );

    // The bound Class 1 model serves the declassify path, but only for a
    // governed slot of UID 703's signed epoch (GAP-27).
    use enclave_model_runnerd::service::{RunnerRequest, RunnerResponse};
    let env = f.env();
    let r = env
        .connect(DaemonId::ModelRunner)
        .unwrap()
        .call::<_, RunnerResponse>(&RunnerRequest::Declassify {
            payload: b"refund request for order 991".to_vec().into(),
            cardinality: 4,
            schema: "ticket.intent".into(),
            slot: None,
        });
    assert!(r.unwrap_err().is("DECLASSIFY_SLOT_REQUIRED"));

    // L1 custody is Touch ID only: FIDO2 custodian enrollment is refused.
    // (L2+ enrollment over simulated CTAP 2.1 is covered by custody tests.)
    let en = f.cli(&["vault", "enroll"]);
    assert!(!en.status.success());
    assert!(String::from_utf8_lossy(&en.stderr).contains("ENROLL_NOT_APPLICABLE_L1"));

    // UID 705 proves an epoch it reconstructs itself (GAP-10): governed
    // slots come from UID 703 (the sequence authority); scrubs are folded from
    // 703's witnesses and journal, an issued-but-unused slot is a tombstone
    // co-signed by 703 and 704 over UDS; the frame is relayed by 702.
    let vault = |r: VaultRequest| -> VaultResponse {
        env.connect(DaemonId::CustodyVault)
            .unwrap()
            .call(&r)
            .unwrap()
    };
    let VaultResponse::Epoch(be) = vault(VaultRequest::BootEpoch) else {
        panic!()
    };
    let mut slots = Vec::new();
    for i in 0..12 {
        if i % 5 == 0 {
            let VaultResponse::Slot { rpc_seq_u64, .. } = vault(VaultRequest::AllocateSlot) else {
                panic!()
            };
            slots.push(rpc_seq_u64);
        } else {
            let VaultResponse::Text(t) = vault(VaultRequest::ScrubText {
                text: format!("ticket {i}: card 4111 1111 1111 1111"),
                bulk_set: false,
                grant: None,
            }) else {
                panic!()
            };
            assert!(!t.contains("4111"));
        }
    }
    let VaultResponse::Status(st) = vault(VaultRequest::Status) else {
        panic!()
    };
    assert_eq!(st.boot_epoch_id, be.boot_epoch_id);
    let (s_end, s_start) = (st.rpc_seq_u64 - 1, st.rpc_seq_u64 - 12);
    assert!(slots.iter().all(|s| (s_start..=s_end).contains(s)));
    let req = ProveEpochRequest {
        boot_epoch_id: be.boot_epoch_id.clone(),
        s_start,
        s_end,
    };
    // L1 hosts emit no compliance rollup. The L2 prove/relay/verify path
    // needs a model admitted through the encrypted custody path (F38), which
    // this development mesh does not provision; it is tracked separately.
    let rollup = env
        .connect(DaemonId::ZkAuditor)
        .unwrap()
        .call::<_, ZkResponse>(&ZkRequest::ProveEpoch(Box::new(req)));
    assert!(rollup.unwrap_err().is("ROLLUP_PROFILE"));

    // GAP-27 acceptance: one governed `declassify_enum` through UID 704 is
    // journaled by UIDs 701, 703 and 704 under the same
    // `(boot_epoch_id, rpc_seq_u64)`, and UID 703's epoch signature verifies
    // against the SEP epoch key both 701 and 704 pinned.
    {
        use enclave_agent_runtime::service::{IfcRequest, IfcResponse};
        use enclave_core::label::{Conf, Label, Taint};
        use enclave_core::user_turn::{AttachmentRef, UserTurnV1};
        let blob = b"refund request for order 991".to_vec();
        let reference = AttachmentRef {
            handle: "$paste_1".into(),
            label: Label::new(Conf::C3, Taint::T3),
            blake3: blake3::hash(&blob).to_hex().to_string(),
            kind: None,
        };
        let ifc = |r: IfcRequest| -> IfcResponse {
            env.connect(DaemonId::AgentRuntime)
                .unwrap()
                .call(&r)
                .unwrap()
        };
        let IfcResponse::Plan { context, .. } = ifc(IfcRequest::SubmitTurn {
            turn: UserTurnV1 {
                directive_short: "triage the ticket".into(),
                attachments: vec![reference],
            },
            attachments: vec![("$paste_1".into(), blob.into())],
            tools: vec![],
            holder_pk: None,
            budget_mb: 12_000,
        }) else {
            panic!()
        };
        let handle = context.attachment_stubs[0].clone();
        let IfcResponse::Handle(_) = ifc(IfcRequest::DeclassifyEnum {
            agent: "triage".into(),
            handle,
            cardinality: 4,
            schema: "ticket.intent".into(),
        }) else {
            panic!()
        };
        let lines = |d: DaemonId| -> Vec<serde_json::Value> {
            let p = f
                .state
                .join("log")
                .join(d.dir_name())
                .join(format!("{}-audit.jsonl", d.plist_suffix()));
            std::fs::read_to_string(&p)
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        };
        let key = |v: &serde_json::Value| {
            (
                v["boot_epoch_id"].as_str().unwrap().to_owned(),
                v["rpc_seq_u64"].as_u64().unwrap(),
            )
        };
        let ifc_line = lines(DaemonId::AgentRuntime)
            .into_iter()
            .rev()
            .find(|l| l["payload"]["event"] == "DECLASSIFY_ENUM")
            .expect("704 line");
        let k = key(&ifc_line);
        assert_eq!(k.0, be.boot_epoch_id, "governed under UID 703's epoch");
        assert_eq!(ifc_line["payload"]["slot"].as_u64(), Some(k.1));
        let runner_line = lines(DaemonId::ModelRunner)
            .into_iter()
            .rev()
            .find(|l| l["payload"]["event"] == "DECLASSIFY")
            .expect("701 line");
        assert_eq!(key(&runner_line), k);
        assert!(
            lines(DaemonId::CustodyVault)
                .iter()
                .any(|l| l["payload"]["event"] == "SLOT_ISSUED" && key(l) == k),
            "703 line for {k:?}"
        );
        enclave_crypto::epoch::verify(&be).unwrap();
        for d in [DaemonId::ModelRunner, DaemonId::AgentRuntime] {
            let sealed: serde_json::Value = serde_json::from_slice(
                &std::fs::read(
                    f.state
                        .join("daemon-state")
                        .join(d.dir_name())
                        .join("epoch-signer.sealed"),
                )
                .unwrap(),
            )
            .unwrap();
            let pin: serde_json::Value =
                serde_json::from_str(sealed["body"].as_str().unwrap()).unwrap();
            assert_eq!(
                pin["signer_public_key"].as_str().unwrap(),
                hex::encode(&be.signer_public_key),
                "{d} pinned UID 703's epoch key"
            );
        }
    }

    // Budget still holds after every engine has run.
    check_budget(&f.ok(&["daemon", "status"]), "after-load");

    // Internal chains verify, but unanchored input cannot prove no truncation.
    let output = f.cli(&["audit", "verify"]);
    assert_eq!(output.status.code(), Some(4));
    let rep: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        rep.as_array()
            .unwrap()
            .iter()
            .all(|j| j["ok"] == true && j["truncation_checked"] == false
                && j["entries"].as_u64().unwrap() > 0),
        "{rep:#}"
    );
    let files = journal_files(&f.state.join("log"));
    // L1: UID 705 emits no compliance rollup, so it writes no journal.
    assert!(files.len() >= 4, "{files:?}");
    let victim = files
        .iter()
        .find(|p| p.to_string_lossy().contains("cas-audit"))
        .unwrap()
        .clone();
    let mut b = std::fs::read(&victim).unwrap();
    // The test controller captures this pristine fixture checkpoint before
    // tampering. This models a separately held pin, not off-host attestation.
    let anchor = enclave_core::audit::verify_journal(&victim, None).unwrap().anchor;
    let anchor_path = f.state.join("fixture-checkpoint.json");
    std::fs::write(&anchor_path, serde_json::to_vec(&anchor).unwrap()).unwrap();
    let copy = f.state.join("checkpointed-audit.jsonl");
    std::fs::write(&copy, &b).unwrap();
    let anchored = f.ok(&[
        "audit", "verify", "--path", copy.to_str().unwrap(),
        "--anchor", anchor_path.to_str().unwrap(),
    ]);
    assert_eq!(anchored[0]["ok"], true);
    assert_eq!(anchored[0]["truncation_checked"], true);
    assert_eq!(anchored[0]["entries"], anchor.entries);
    let last_line = b[..b.len() - 1].iter().rposition(|c| *c == b'\n').unwrap() + 1;
    std::fs::write(&copy, &b[..last_line]).unwrap();
    let truncated = f.cli(&[
        "audit", "verify", "--path", copy.to_str().unwrap(),
        "--anchor", anchor_path.to_str().unwrap(),
    ]);
    assert_eq!(truncated.status.code(), Some(4));
    let truncated: serde_json::Value = serde_json::from_slice(&truncated.stdout).unwrap();
    assert_eq!(truncated[0]["ok"], false);
    assert!(truncated[0]["error"].as_str().unwrap().contains("AUDIT_TRUNCATED"));
    let i = b.iter().position(|c| *c == b'"').unwrap() + 1;
    b[i] ^= 0x01;
    let copy = f.state.join("tampered-audit.jsonl");
    std::fs::write(&copy, b).unwrap();
    let o = f.cli(&["audit", "verify", "--path", copy.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(4));
    let tampered: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(tampered[0]["ok"], false);

    // Stop: everything goes away; status reports unhealthy.
    f.ok(&["daemon", "stop"]);
    let o = f.cli(&["daemon", "status"]);
    assert_eq!(o.status.code(), Some(3));
}

#[test]
fn launchd_assets_are_reproducible() {
    let out = tmp();
    let l = mcp_enclave::launchd::Layout::default();
    mcp_enclave::launchd::render_all(&out, &l).unwrap();
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../launchd");
    for e in std::fs::read_dir(&out).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap();
        let committed = std::fs::read_to_string(repo.join(name)).unwrap_or_else(|_| {
            panic!(
                "launchd/{} not committed; run `mcp-enclave launchd render --out launchd`",
                name.to_string_lossy()
            )
        });
        assert_eq!(
            committed,
            std::fs::read_to_string(&p).unwrap(),
            "launchd/{} drifted from the generator",
            name.to_string_lossy()
        );
    }
    for d in DaemonId::ALL {
        let s = mcp_enclave::launchd::plist(d, &l);
        assert!(s.contains(&format!("<string>{}</string>", d.account())));
        assert!(s.contains(&format!("<integer>{}</integer>", d.rss_ceiling_bytes())));
        assert!(s.contains("<key>Core</key>\n\t\t<integer>0</integer>"));
        let sb = mcp_enclave::launchd::sandbox_profile(d, &l);
        assert!(sb.contains("(deny default)"));
        // Seatbelt matches resolved paths (/var -> /private/var on macOS).
        assert!(
            !sb.contains("\"/var/") && !sb.contains("\"/tmp/"),
            "{d}: unresolved path in profile"
        );
        let sl = l.for_seatbelt();
        assert_eq!(
            sb.contains("tcp"),
            d == DaemonId::SwarmSync,
            "only UID 702 may hold IP sockets"
        );
        assert_eq!(
            sb.contains("udp"),
            d == DaemonId::SwarmSync,
            "only UID 702 may hold UDP sockets"
        );
        // GAP-01 / GAP-36: writes only to this daemon's own directories.
        for other in DaemonId::ALL.into_iter().filter(|o| *o != d) {
            for root in [&sl.socket_dir, &sl.audit_dir, &sl.state_dir] {
                let forbidden = format!("file-write* (subpath \"{root}/{}\")", other.dir_name());
                assert!(
                    !sb.contains(&forbidden) && !sb.contains(&format!("(subpath \"{root}\") ")),
                    "{d}: {forbidden}"
                );
            }
        }
        assert!(
            !sb.contains(&format!("file-write* (subpath \"{}\")", sl.audit_dir)),
            "{d} may not write the shared journal root"
        );
        // GAP-10: only the prover reads the other daemons' journals.
        assert_eq!(
            sb.contains(&format!(
                "(allow file-read* (subpath \"{}\"))",
                sl.audit_dir
            )),
            d == DaemonId::ZkAuditor,
            "{d}"
        );
        // GAP-15 / GAP-36: the executable (an .app for UID 703) is the only
        // exec target, and every daemon can read the local cdhash pins.
        let exe = mcp_enclave::launchd::program(d, &l);
        assert!(
            s.contains(&format!("<string>{exe}</string>"))
                && sb.contains(&format!("(allow process-exec (literal \"{exe}\"))")),
            "{d}"
        );
        assert_eq!(
            exe.starts_with(&format!("{}/Contents/MacOS/", l.custody_app)),
            d == DaemonId::CustodyVault,
            "{d}"
        );
        assert!(
            sb.contains(&format!(
                "(allow file-read* (literal \"{}\"))",
                enclave_core::codesign::PIN_FILE
            )),
            "{d}"
        );
        assert!(
            sb.contains("IOPMrootDomain"),
            "{d}: missing IOPMrootDomain for GAP-16"
        );
        assert!(
            sb.contains("com.apple.iokit.powerdxpc"),
            "{d}: missing powerdxpc for GAP-16"
        );
        assert!(
            sb.contains("com.enterprise.enclave.exception"),
            "{d}: missing exception port for GAP-12"
        );
        assert_eq!(
            sb.contains("com.apple.ctkd.token-client") && sb.contains("com.apple.SecurityServer"),
            d == DaemonId::CustodyVault,
            "{d}: only UID 703 talks to the SEP"
        );
        if d == DaemonId::ModelRunner {
            assert!(
                sb.contains("AGXDeviceUserClient")
                    && sb.contains("IOAccelerator")
                    && sb.contains("IOSurfaceRootUserClient")
                    && sb.contains("com.apple.AGXCompilerService"),
                "{d}: missing Metal/MLX services for GAP-17"
            );
        }
        // Group memberships (client groups, journal readers) need initgroups(3).
        assert!(s.contains("<key>InitGroups</key>\n\t<true/>"), "{d}");
        assert!(
            s.contains(&format!(
                "<string>--state-dir</string>\n\t\t<string>{}/{}</string>",
                l.state_dir,
                d.dir_name()
            )),
            "{d}"
        );
    }
    let pv_j = mcp_enclave::launchd::provision_script(&l);
    let jg = mcp_enclave::launchd::JOURNAL_READ_GROUP;
    assert!(pv_j.contains(&format!("addmember {jg} {}", DaemonId::ZkAuditor.account())));
    assert_eq!(
        pv_j.matches(&format!("addmember {jg} ")).count(),
        1,
        "UID 705 is the only journal reader"
    );
    for d in DaemonId::ALL {
        assert!(pv_j.contains(&format!(
            "mkdirp {}/{} {} {jg} 2750",
            l.audit_dir,
            d.dir_name(),
            d.account()
        )));
    }
    // Provisioning creates exactly the client groups of the adjacency matrix.
    let pv = mcp_enclave::launchd::provision_script(&l);
    for server in DaemonId::ALL {
        assert!(pv.contains(&format!(
            "mkgroup {} {}",
            server.client_group(),
            server.client_gid()
        )));
        assert!(pv.contains(&format!(
            "mkdirp {}/{} {} {} 2750",
            l.socket_dir,
            server.dir_name(),
            server.account(),
            server.client_group()
        )));
        for c in DaemonId::ALL {
            let line = format!("addmember {} {}", server.client_group(), c.account());
            assert_eq!(
                pv.contains(&line),
                enclave_core::ipc::production_policy(server)
                    .allowed_uids
                    .contains(&c.uid()),
                "{line}"
            );
        }
    }
    // GAP-21: the root revocation supervisor, reachable by UID 702 only.
    let sup = std::fs::read_to_string(
        out.join(format!("{}.plist", enclave_core::supervisor::LAUNCHD_LABEL)),
    )
    .unwrap();
    assert!(
        sup.contains("<string>supervise</string>")
            && sup.contains("<key>UserName</key>\n\t<string>root</string>")
            && sup.contains("<key>com.enterprise.enclave.exception</key>")
    );
    let sg = enclave_core::supervisor::CLIENT_GROUP;
    assert_eq!(pv.matches(&format!("addmember {sg} ")).count(), 1);
    assert!(pv.contains(&format!("addmember {sg} {}", DaemonId::SwarmSync.account())));
    assert!(pv.contains(&format!(
        "mkdirp {}/supervisor root {sg} 2750",
        l.socket_dir
    )));
    // GAP-10: dedicated witness channel assertion
    assert!(pv.contains(&format!(
        "mkgroup {} {}",
        enclave_core::daemon::WITNESS_CLIENT_GROUP,
        enclave_core::daemon::WITNESS_CLIENT_GID
    )));
    assert!(pv.contains(&format!(
        "addmember {} {}",
        enclave_core::daemon::WITNESS_CLIENT_GROUP,
        DaemonId::CustodyVault.account()
    )));
    assert!(pv.contains(&format!(
        "mkdirp {}/{} {} {} 2750",
        l.socket_dir,
        enclave_core::daemon::WITNESS_SOCKET_DIR,
        DaemonId::ZkAuditor.account(),
        enclave_core::daemon::WITNESS_CLIENT_GROUP
    )));
    // ADR-006 amendment: no enclave group in macOS's File Sharing GID range.
    let mut gids: Vec<u32> = DaemonId::ALL
        .iter()
        .flat_map(|d| [d.gid(), d.client_gid()])
        .collect();
    gids.extend([
        enclave_core::supervisor::CLIENT_GID,
        mcp_enclave::launchd::JOURNAL_READ_GID,
        enclave_core::daemon::WITNESS_CLIENT_GID,
    ]);
    for g in &gids {
        assert!(
            !(700..800).contains(g),
            "gid {g} collides with com.apple.sharepoint.group.N"
        );
    }
    gids.sort_unstable();
    gids.dedup();
    assert_eq!(gids.len(), 13, "every enclave group has its own gid");
    let ent = mcp_enclave::launchd::entitlements();
    assert!(ent.contains("<key>com.apple.security.cs.allow-jit</key>\n\t<false/>"));
    assert!(!ent.contains("<true/>"));
    let _ = std::fs::remove_dir_all(out);
}

#[test]
fn grant_key_provisioning_is_idempotent_and_split_by_owner() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let st = tmp();
    for d in [DaemonId::AgentRuntime, DaemonId::CustodyVault] {
        std::fs::create_dir_all(st.join(d.dir_name())).unwrap();
    }
    if enclave_core::ipc::geteuid() != 0 {
        // chown needs root; the provisioning step is root-only by design.
        assert!(mcp_enclave::launchd::provision_grant_key(&st)
            .unwrap_err()
            .is("GRANT_KEY_CHOWN"));
        let _ = std::fs::remove_dir_all(st);
        return;
    }
    let pk = mcp_enclave::launchd::provision_grant_key(&st).unwrap();
    assert_eq!(pk.len(), 64);
    // Re-install keeps the key.
    assert_eq!(mcp_enclave::launchd::provision_grant_key(&st).unwrap(), pk);
    let seed = st.join("ifc").join(mcp_enclave::launchd::GRANT_SEED_FILE);
    let public = st
        .join("custody")
        .join(mcp_enclave::launchd::GRANT_PUBLIC_FILE);
    for (p, d) in [
        (&seed, DaemonId::AgentRuntime),
        (&public, DaemonId::CustodyVault),
    ] {
        let m = std::fs::metadata(p).unwrap();
        assert_eq!(
            (m.uid(), m.gid(), m.permissions().mode() & 0o777),
            (d.uid(), d.gid(), 0o600),
            "{}",
            p.display()
        );
    }
    assert_eq!(std::fs::read_to_string(&public).unwrap(), pk);
    // A corrupt seed is refused, never silently replaced.
    std::fs::write(&seed, "zz").unwrap();
    assert!(mcp_enclave::launchd::provision_grant_key(&st)
        .unwrap_err()
        .is("GRANT_SEED_INVALID"));
    let _ = std::fs::remove_dir_all(st);
}

#[test]
fn fido_emulator_is_opt_in_and_isolated() {
    use enclave_custody_vaultd::ctap::transport as fido;
    use mcp_enclave::launchd::{self, Layout};
    // Default (production): physical key over IOKit HID, no emulator anywhere.
    let l = Layout::default();
    let custody = launchd::plist(DaemonId::CustodyVault, &l);
    assert!(custody.contains("<string>--yubikey-transport</string>\n\t\t<string>hid</string>"));
    assert!(!launchd::provision_script(&l).contains(fido::EMULATOR_ACCOUNT));
    let out = tmp();
    launchd::render_all(&out, &l).unwrap();
    assert!(!out.join(format!("{}.plist", launchd::FIDO_LABEL)).exists());
    let _ = std::fs::remove_dir_all(&out);
    // Opt-in: UID 703 is pointed at the emulator socket; the emulator runs
    // as its own account under a profile with no network and no IOKit, and
    // only _piivault may connect to it.
    let l = Layout {
        fido_emulator: true,
        ..Layout::default()
    };
    let custody = launchd::plist(DaemonId::CustodyVault, &l);
    assert!(custody.contains(&format!("<string>emulated:{}</string>", l.fido_socket())));
    let p = launchd::fido_plist(&l);
    assert!(p.contains(&format!(
        "<key>UserName</key>\n\t<string>{}</string>",
        fido::EMULATOR_ACCOUNT
    )));
    assert!(p.contains("/usr/bin/sandbox-exec"));
    let sb = launchd::fido_sandbox_profile(&l);
    assert!(
        sb.contains("(deny default)")
            && !sb.contains("tcp")
            && !sb.contains("iokit")
            && !sb.contains("mach-lookup")
    );
    assert!(!sb.contains("\"/var/"), "unresolved path");
    let pv = launchd::provision_script(&l);
    assert!(pv.contains(&format!(
        "mkuser {} {} {}",
        fido::EMULATOR_ACCOUNT,
        fido::EMULATOR_UID,
        fido::EMULATOR_GID
    )));
    assert_eq!(
        pv.matches(&format!("addmember {} ", fido::EMULATOR_CLIENT_GROUP))
            .count(),
        1
    );
    assert!(pv.contains(&format!(
        "addmember {} {}",
        fido::EMULATOR_CLIENT_GROUP,
        DaemonId::CustodyVault.account()
    )));
    for g in [fido::EMULATOR_GID, fido::EMULATOR_CLIENT_GID] {
        assert!(!(700..800).contains(&g));
    }
}
