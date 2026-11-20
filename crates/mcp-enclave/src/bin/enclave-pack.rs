//! `enclave-pack` — Offline model packager for depot (FS-701 §3.1 / §3.2).
//! Packages model weights and companion safety layers into the depot-owned
//! `enclave_adapter.*` tensor namespace, producing `.safetensors` artifacts
//! and signed `enclave-model.manifest.json` descriptors that UID 702 can admit.

use std::path::PathBuf;

use clap::Parser;
use enclave_model_runnerd::manifest::ExecutionClass;
use enclave_model_runnerd::zoo;
use sha2::Digest;

#[derive(Parser, Debug)]
#[command(
    name = "enclave-pack",
    about = "Package model weights into depot CAS-admissible artifacts"
)]
struct Args {
    /// Phase-1 model target: llada-8b, rwkv-7, eagle-3, vjepa-2.
    #[arg(long)]
    target_model: Option<String>,

    /// Explicit ExecutionClass: DISCRETE_DIFFUSION, RECURRENT_SSM_TTT, SPECULATIVE_OR_RECURRENT_DEPTH, etc.
    #[arg(long)]
    class: Option<String>,

    /// Output directory for packaged artifacts.
    #[arg(long, default_value = ".")]
    out_dir: PathBuf,

    /// Optional input safetensors weights file.
    #[arg(long)]
    weights: Option<PathBuf>,

    /// Optional model ID override.
    #[arg(long)]
    model_id: Option<String>,

    /// Directory with a publisher Llama-family checkpoint (config.json,
    /// tokenizer.json, model.safetensors) to repack as `mlx_llama_v1`.
    #[arg(long, conflicts_with = "weights")]
    hf_llama: Option<PathBuf>,

    /// Directory with a Qwen3 target (config.json, tokenizer.json,
    /// model.safetensors) to pair with `--eagle3-head` as `mlx_eagle3_v1`.
    #[arg(long, conflicts_with_all = ["weights", "hf_llama"], requires = "eagle3_head")]
    hf_eagle3_target: Option<PathBuf>,

    /// Directory with the EAGLE-3 draft head (config.json, model.safetensors).
    #[arg(long, requires = "hf_eagle3_target")]
    eagle3_head: Option<PathBuf>,

    /// Directory with a V-JEPA 2 checkpoint (config.json, model.safetensors)
    /// to repack as `mlx_vjepa2_v1` with the planner's adapter heads.
    #[arg(long, conflicts_with_all = ["weights", "hf_llama", "hf_eagle3_target"])]
    hf_vjepa2: Option<PathBuf>,

    /// Directory with the LLaDA checkpoint (config.json, tokenizer.json,
    /// model.safetensors.index.json and its shards) to quantize and repack as
    /// `mlx_llada_v1`. Shards are read one at a time.
    #[arg(long, conflicts_with_all = ["weights", "hf_llama", "hf_eagle3_target", "hf_vjepa2"])]
    hf_llada: Option<PathBuf>,

    /// `--hf-llada` only: bits per quantized block weight (4 or 8).
    #[arg(long, default_value_t = 4, requires = "hf_llada")]
    llada_bits: u32,

    /// `--hf-llada` only: bits per quantized output-head weight (4 or 8).
    #[arg(long, default_value_t = 8, requires = "hf_llada")]
    llada_head_bits: u32,

    /// DISCRETE_DIFFUSION only: signed generation deadline in ms
    /// (bind refuses a value above the profile ceiling).
    #[arg(long)]
    diffusion_deadline_ms: Option<u32>,

    /// RECURRENT_SSM_TTT only: anchor mix alpha in [0.25, 1.0]. A real
    /// recurrent model needs < 1.0, because 1.0 resets the session to the
    /// system state at the Ingest -> Generate boundary and erases the prompt.
    #[arg(long)]
    anchor_mix_alpha: Option<f64>,
}

fn resolve_class(target: Option<&str>, class_str: Option<&str>) -> Result<ExecutionClass, String> {
    if let Some(t) = target {
        match t.to_ascii_lowercase().as_str() {
            "llada-8b" | "llada" => Ok(ExecutionClass::DiscreteDiffusion),
            "rwkv-7" | "rwkv" | "mamba-3" => Ok(ExecutionClass::RecurrentSsmTtt),
            "eagle-3" | "eagle" | "huginn" => Ok(ExecutionClass::SpeculativeOrRecurrentDepth),
            "vjepa-2" | "vjepa" | "v-jepa-2" => Ok(ExecutionClass::JepaEbmWorldPlanner),
            "rlcd" | "jev" => Ok(ExecutionClass::DiscriminativeRlcd),
            "blt" | "lcm" => Ok(ExecutionClass::ByteOrConcept),
            "ar" | "causal" => Ok(ExecutionClass::ArCausal),
            other => ExecutionClass::parse(other).map_err(|e| format!("{e:?}")),
        }
    } else if let Some(c) = class_str {
        ExecutionClass::parse(c).map_err(|e| format!("{e:?}"))
    } else {
        Err("either --target-model or --class must be specified".into())
    }
}

/// Quantize a sharded LLaDA checkpoint shard by shard (peak memory: one
/// shard plus the packed output).
fn repack_llada(dir: &std::path::Path, bits: u32, head_bits: u32) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use enclave_model_runnerd::backends::mlx::llada::LladaPacker;
    let read = |name: &str| std::fs::read_to_string(dir.join(name));
    let mut packer = LladaPacker::new(&read("config.json")?, &read("tokenizer.json")?, bits, head_bits)
        .map_err(|e| format!("LLaDA config: {e}"))?;
    let index: serde_json::Value = serde_json::from_str(&read("model.safetensors.index.json")?)?;
    let shards: std::collections::BTreeSet<String> = index["weight_map"].as_object().ok_or("index weight_map")?
        .values().filter_map(|v| v.as_str().map(str::to_owned)).collect();
    for shard in shards {
        if shard.contains('/') || shard.starts_with('.') {
            return Err(format!("shard name refused: {shard}").into());
        }
        let bytes = std::fs::read(dir.join(&shard))?;
        let idx = enclave_model_runnerd::safetensors::parse(&bytes).map_err(|e| format!("{shard}: {e}"))?;
        for (name, t) in &idx.tensors {
            packer.add(name, &t.dtype, &t.shape, &bytes[t.range.0..t.range.1]).map_err(|e| format!("{shard} {name}: {e}"))?;
        }
        println!("Quantized {shard} ({} tensors)", idx.tensors.len());
    }
    Ok(packer.finish().map_err(|e| format!("LLaDA finish: {e}"))?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let class = resolve_class(args.target_model.as_deref(), args.class.as_deref())
        .map_err(|e| format!("Invalid target/class: {e}"))?;

    println!(
        "Packaging Phase-1 / Tier-1 model for class: {}",
        class.name()
    );

    let model_id_str = args
        .model_id
        .clone()
        .or_else(|| args.target_model.clone())
        .unwrap_or_else(|| "model".into());

    let repacked = match &args.hf_llama {
        Some(dir) => {
            let read = |name: &str| std::fs::read_to_string(dir.join(name));
            Some(enclave_model_runnerd::backends::mlx::llama::repack_hf(
                &read("config.json")?, &read("tokenizer.json")?, &std::fs::read(dir.join("model.safetensors"))?,
            ).map_err(|e| format!("Repack error: {e}"))?)
        }
        None => None,
    };
    let repacked = match (&args.hf_eagle3_target, &args.eagle3_head) {
        (Some(target), Some(head)) => {
            let read = |dir: &PathBuf, name: &str| std::fs::read_to_string(dir.join(name));
            Some(enclave_model_runnerd::backends::mlx::eagle3::repack(
                &read(target, "config.json")?, &read(target, "tokenizer.json")?,
                &std::fs::read(target.join("model.safetensors"))?,
                &read(head, "config.json")?, &std::fs::read(head.join("model.safetensors"))?,
            ).map_err(|e| format!("Repack error: {e}"))?)
        }
        _ => repacked,
    };
    let repacked = match &args.hf_vjepa2 {
        Some(dir) => Some(enclave_model_runnerd::backends::mlx::vjepa2::repack(
            &std::fs::read_to_string(dir.join("config.json"))?, &std::fs::read(dir.join("model.safetensors"))?,
        ).map_err(|e| format!("Repack error: {e}"))?),
        None => repacked,
    };
    let repacked = match &args.hf_llada {
        Some(dir) => Some(repack_llada(dir, args.llada_bits, args.llada_head_bits)?),
        None => repacked,
    };
    let mut packaged = if let Some(weights_bytes) = repacked.or(args.weights.map(std::fs::read).transpose()?) {
        let mut pkg = zoo::package(class).map_err(|e| format!("Zoo package error: {e}"))?;
        pkg.weights = weights_bytes;
        let b3 = blake3::hash(&pkg.weights).to_hex().to_string();
        let sha = hex::encode(sha2::Sha256::digest(&pkg.weights));
        pkg.manifest["artifact"]["blake3"] = serde_json::json!(b3);
        pkg.manifest["artifact"]["cas_uri"] = serde_json::json!(format!(
            "cas://blake3-bao-v1/{b3}?target={model_id_str}&ns=models&min_profile=L1"
        ));
        pkg.manifest["artifact"]["sha256"] = serde_json::json!(sha);
        pkg
    } else {
        let mut pkg = zoo::package(class).map_err(|e| format!("Zoo package error: {e}"))?;
        let b3 = pkg.manifest["artifact"]["blake3"]
            .as_str()
            .unwrap_or("")
            .to_string();
        if !b3.is_empty() {
            pkg.manifest["artifact"]["cas_uri"] = serde_json::json!(format!(
                "cas://blake3-bao-v1/{b3}?target={model_id_str}&ns=models&min_profile=L1"
            ));
        }
        pkg
    };

    packaged.manifest["model_id"] = serde_json::json!(model_id_str);
    if let Some(alpha) = args.anchor_mix_alpha {
        if class != ExecutionClass::RecurrentSsmTtt || !(0.25..=1.0).contains(&alpha) {
            return Err("--anchor-mix-alpha needs RECURRENT_SSM_TTT and a value in [0.25, 1.0]".into());
        }
        packaged.manifest["security_controls"]["anchor_mix_alpha"] = serde_json::json!(alpha);
    }

    if let Some(ms) = args.diffusion_deadline_ms {
        if class != ExecutionClass::DiscreteDiffusion {
            return Err("--diffusion-deadline-ms needs DISCRETE_DIFFUSION".into());
        }
        packaged.manifest["output_caps"]["diffusion_deadline_ms"] = serde_json::json!(ms);
    }

    std::fs::create_dir_all(&args.out_dir)?;

    let model_id = packaged.manifest["model_id"].as_str().unwrap_or("model");
    if model_id.is_empty()
        || model_id.len() > 128
        || !model_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err("model_id must be a 1–128 character ASCII identifier (letters, digits, underscore, hyphen)".into());
    }
    let weights_filename = format!("{model_id}.safetensors");
    let manifest_filename = format!("{model_id}.manifest.json");

    let weights_path = args.out_dir.join(&weights_filename);
    let manifest_path = args.out_dir.join(&manifest_filename);

    std::fs::write(&weights_path, &packaged.weights)?;
    println!(
        "Wrote weights: {} ({} bytes)",
        weights_path.display(),
        packaged.weights.len()
    );

    let manifest_bytes = serde_json::to_vec_pretty(&packaged.manifest)?;
    std::fs::write(&manifest_path, &manifest_bytes)?;
    println!(
        "Wrote manifest: {} ({} bytes)",
        manifest_path.display(),
        manifest_bytes.len()
    );

    if let Some(corpus) = packaged.corpus {
        let corpus_filename = format!("{model_id}.calib.jsonl");
        let corpus_path = args.out_dir.join(&corpus_filename);
        std::fs::write(&corpus_path, &corpus)?;
        println!(
            "Wrote calibration corpus: {} ({} bytes)",
            corpus_path.display(),
            corpus.len()
        );
    }

    println!("Model packaging complete. Ready for admission by UID 702 (enclave-swarm-syncd).");
    Ok(())
}
