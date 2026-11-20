//! Offline compiler and signer. This binary is never linked into the daemon.
use enclave_tool_host::artifacts::{sign_manifest, ApprovedModuleV1, ArtifactManifestV1};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Recipe {
    valid_for_seconds: u64,
    tools: Vec<Tool>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Tool {
    server: String,
    tool_name: String,
    source: PathBuf,
    tools_list: serde_json::Value,
    max_rows: u64,
}
fn read(path: &Path, max: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    if !f.metadata()?.is_file() || f.metadata()?.len() > max {
        return Err("input limit/type".into());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut f).take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err("input grew beyond limit".into());
    }
    Ok(bytes)
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
fn main() {
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let args: Vec<_> = std::env::args().collect();
        if args.len() != 4 {
            return Err("usage: enclave-tool-build RECIPE_JSON PRIVATE_BUILD_SEED_HEX_FILE OUTPUT_DIRECTORY".into());
        }
        let key_path = Path::new(&args[2]);
        let meta = std::fs::symlink_metadata(key_path)?;
        // SAFETY: geteuid has no preconditions.
        if !meta.is_file()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o077 != 0
            || meta.nlink() != 1
        {
            return Err("build key must be an owned private single-link file".into());
        }
        let seed_text = read(key_path, 128)?;
        let seed: [u8; 32] = hex::decode(std::str::from_utf8(&seed_text)?.trim())?
            .try_into()
            .map_err(|_| "expected 32-byte build seed")?;
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let recipe: Recipe = serde_json::from_slice(&read(Path::new(&args[1]), 1024 * 1024)?)?;
        if recipe.tools.is_empty()
            || recipe.tools.len() > 8
            || recipe.valid_for_seconds == 0
            || recipe.valid_for_seconds > 86_400
        {
            return Err("recipe count/lifetime limit".into());
        }
        let directory = Path::new(&args[3]).canonicalize()?;
        let metadata = directory.metadata()?;
        // SAFETY: geteuid has no preconditions.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err("output directory must already be private and owned".into());
        }
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true).max_wasm_stack(512 * 1024);
        let engine = wasmtime::Engine::new(&config)?;
        let mut modules = Vec::new();
        let mut total = 0usize;
        for tool in recipe.tools {
            let input = read(&tool.source, 64 * 1024 * 1024)?;
            // Native input is never accepted for signing: compile validated Wasm.
            let compiled = wasmtime::Module::new(&engine, &input)
                .map_err(|e| format!("OFFLINE_WASM_INPUT: {e}"))?
                .serialize()?;
            total = total
                .checked_add(compiled.len())
                .ok_or("artifact size overflow")?;
            if total > 64 * 1024 * 1024 {
                return Err("compiled artifact aggregate limit".into());
            }
            let digest = *blake3::hash(&compiled).as_bytes();
            let file_name = format!("{}.cwasm", hex::encode(digest));
            let path = directory.join(&file_name);
            if path.exists() {
                if read(&path, 64 * 1024 * 1024)? != compiled {
                    return Err("existing artifact differs".into());
                }
            } else {
                write_new(&path, &compiled)?;
            }
            modules.push(ApprovedModuleV1 {
                server: tool.server,
                tool_name: tool.tool_name,
                file_name,
                module_blake3: digest,
                tools_list: tool.tools_list,
                row_format: enclave_tool_host::ticket::RowFormat::JsonArray,
                max_rows: tool.max_rows,
            });
        }
        let now = enclave_tool_host::lifecycle::trusted_unix_ns()?;
        let signed = sign_manifest(
            ArtifactManifestV1 {
                v: 1,
                issued_at_unix_ns: now,
                expires_at_unix_ns: now
                    .checked_add(recipe.valid_for_seconds * 1_000_000_000)
                    .ok_or("expiry overflow")?,
                modules,
            },
            &key,
        )?;
        write_new(
            &directory.join("manifest.json"),
            &serde_json::to_vec(&signed)?,
        )?;
        std::fs::File::open(&directory)?.sync_all()?;
        println!("offline-built manifest.json; configure its public build key independently at the daemon");
        Ok(())
    })();
    if let Err(e) = result {
        eprintln!("offline build refused: {e}");
        std::process::exit(1);
    }
}
