//! Local compliance ledger gateway binary (GAP-26).

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use enclave_core::error::EnclaveResult;
use enclave_zk_auditor::zk::manifest::VkManifestV1;
use ledger_gateway::{serve_tcp, Ledger, LedgerGateway};

fn main() -> EnclaveResult<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut listen_addr = "127.0.0.1:8725".to_string();
    let mut key_id = 1u8;
    let mut run = false;
    let mut journal: Option<std::path::PathBuf> = None;
    let mut state_dir: Option<std::path::PathBuf> = None;
    let mut dev_in_memory = false;
    let mut key_file: Option<std::path::PathBuf> = None;
    let mut max_frames = ledger_gateway::DEFAULT_MAX_FRAMES;
    let mut receiver_trust_file:Option<std::path::PathBuf>=None;
    let mut accounting_fixture=false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--receiver-trust-file"=>{
                receiver_trust_file=Some(args.get(i+1).ok_or_else(||usage("--receiver-trust-file needs a path"))?.into());i+=1;
            }
            "--accounting-fixture"=>accounting_fixture=true,
            "--key-file" => {
                key_file = Some(
                    args.get(i + 1)
                        .ok_or_else(|| usage("--key-file needs a path"))?
                        .into(),
                );
                i += 1;
            }
            "--listen" => {
                listen_addr = args.get(i + 1).ok_or_else(|| usage("--listen needs an address"))?.clone();
                i += 1;
            }
            "--key-id" => {
                key_id = args.get(i + 1).ok_or_else(|| usage("--key-id needs a number"))?
                    .parse().map_err(|_| usage("--key-id must be an integer from 0 to 255"))?;
                i += 1;
            }
            "--ledger-journal" => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| usage("--ledger-journal needs a path"))?;
                journal = Some(v.into());
                i += 1;
            }
            "--state-dir" => {
                state_dir = Some(args.get(i + 1).ok_or_else(|| usage("--state-dir needs a path"))?.into());
                i += 1;
            }
            "--dev-in-memory" => dev_in_memory = true,
            "--max-frames" => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| usage("--max-frames needs a number"))?;
                max_frames = v
                    .parse::<usize>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| usage("--max-frames must be a positive integer"))?;
                i += 1;
            }
            "--run" => {
                run = true;
            }
            "--help" | "-h" => {
                println!("Local test fixture: the verifier digest is compiled in, not authenticated by TUF. Do not treat this binary as a production trust anchor.");
                println!("  --receiver-trust-file PATH  bounded protected operator-owned issuer/cohort document (required unless --accounting-fixture)");
                println!("  --accounting-fixture       explicit accounting-only mode; no issuer/cohort authentication");
                println!("  --key-file PATH   persist a private OHTTP identity (0600); publish its public config to test hosts. Without it identity is ephemeral.");
                println!("Usage: ledger-gateway [--listen <addr:port>] [--key-id <id>] [--key-file <path>] [--state-dir <dir> | --ledger-journal <path> | --dev-in-memory] [--max-frames <n>] (--receiver-trust-file <path> | --accounting-fixture) [--run]");
                println!("  --ledger-journal  append-only, hash-chained ledger file (0600); replayed at start.");
                println!("  --state-dir DIR   durable ledger at DIR/frames.jsonl (default {}).", ledger_gateway::ledger::DEFAULT_STATE_DIR);
                println!("                    Creates DIR as 0700 under an existing owned parent without group/other writes.");
                println!("                    Wrong modes, corruption, locks and storage errors refuse startup; no memory fallback.");
                println!("  --dev-in-memory   explicit development-only mode; all replay/order history is lost on restart.");
                println!("  --max-frames      hard capacity; further frames are refused LEDGER_FULL (default {}).", ledger_gateway::DEFAULT_MAX_FRAMES);
                return Ok(());
            }
            other => return Err(usage(&format!("unknown argument: {other}"))),
        }
        i += 1;
    }

    if accounting_fixture==receiver_trust_file.is_some() {
        return Err(usage("select exactly one of --receiver-trust-file or --accounting-fixture"));
    }
    let receiver_trust=receiver_trust_file.as_deref().map(enclave_zk_auditor::receiver_trust::ReceiverTrust::from_operator_file).transpose()?;

    if state_dir.is_some() && journal.is_some() {
        return Err(usage("--state-dir conflicts with --ledger-journal"));
    }
    if dev_in_memory && (state_dir.is_some() || journal.is_some()) {
        return Err(usage("--dev-in-memory conflicts with durable storage options"));
    }

    // Resolve and validate storage before starting a listener or publishing an
    // identity. The default can never silently become a volatile ledger.
    let ledger = if dev_in_memory {
        if max_frames > ledger_gateway::ledger::HARD_MAX_FRAMES {
            return Err(usage("--max-frames exceeds the hard capacity ceiling"));
        }
        Ledger::in_memory(max_frames)
    } else if let Some(ref path) = journal {
        Ledger::open(path, max_frames)?
    } else {
        let directory = state_dir.unwrap_or_else(|| ledger_gateway::ledger::DEFAULT_STATE_DIR.into());
        Ledger::open_state_dir(&directory, max_frames)?
    };
    let journal = ledger.journal_path().map(std::path::Path::to_path_buf);

    let manifest = VkManifestV1::production_hiding();
    let (cfg, sk) = match key_file {
        Some(ref path) => ledger_gateway::key_store::load_or_create(path, key_id)?,
        None => enclave_crypto::ohttp::gateway_keypair(key_id),
    };
    let gw = LedgerGateway::with_ledger(cfg.clone(), sk, manifest, ledger);
    let gw=match receiver_trust {Some(trust)=>gw.with_receiver_trust(trust),None=>gw.accounting_fixture()};
    println!("  Receiver authority: {}",if accounting_fixture {"ACCOUNTING FIXTURE ONLY"} else {"operator pinned issuer/cohort; compiled accounting VK remains a local fixture"});
    println!("ledger-gateway v3.0.0 (local OHTTP range-proof fixture; not a production compliance trust anchor)");
    println!("  Gateway key config: {}", cfg.render());
    println!("  Compiled vk_digest: {}", gw.manifest().vk_digest);
    println!(
        "  OHTTP identity:     {}",
        if key_file.is_some() {
            "persistent"
        } else {
            "ephemeral; restart requires republishing test-host config"
        }
    );
    println!("  Authority / path:   https://ledger.corporate.internal/v1/rollup");
    println!("  Listen address:     {}", listen_addr);
    match &journal {
        Some(p) => println!(
            "  Ledger journal:     {} ({} frames)",
            p.display(),
            gw.verified_frames().len()
        ),
        None => println!("  Ledger journal:     none (explicit development mode; lost on restart)"),
    }

    if run {
        let listener = std::net::TcpListener::bind(&listen_addr)
            .map_err(|e| enclave_core::err!(EIO, "TCP_BIND", "{e}"))?;
        let stop = Arc::new(AtomicBool::new(false));
        println!("Listening for OHTTP rollup requests...");
        serve_tcp(listener, Arc::new(gw), stop)?;
    }

    Ok(())
}

fn usage(msg: &str) -> enclave_core::error::EnclaveError {
    enclave_core::err!(EINVAL, "USAGE", "{msg}")
}
