use super::*;

/// A tiny LLaDA-shaped publisher config (group 64 divides every width).
fn config(overrides: &[(&str, Value)]) -> String {
    let mut c = json!({
        "model_type": "llada", "block_type": "llama", "activation_type": "silu",
        "layer_norm_type": "rms", "layer_norm_with_affine": true, "rope": true, "alibi": false,
        "include_bias": false, "include_qkv_bias": false, "bias_for_layer_norm": false,
        "attention_layer_norm": false, "input_emb_norm": false, "scale_logits": false,
        "weight_tying": false, "block_group_size": 1, "rope_scaling": null,
        "d_model": 64, "n_heads": 2, "n_kv_heads": 2, "n_layers": 1, "mlp_hidden_size": 128,
        "embedding_size": 320, "vocab_size": 257, "rope_theta": 500000.0, "rms_norm_eps": 1e-5,
        "mask_token_id": 256,
    });
    for (k, v) in overrides {
        c[*k] = v.clone();
    }
    c.to_string()
}

fn ramp(n: usize, seed: f32) -> Vec<f32> {
    (0..n)
        .map(|i| ((i as f32 * 0.37 + seed).sin()) * 0.05)
        .collect()
}

fn bf16_bytes(v: &[f32]) -> Vec<u8> {
    v.iter()
        .flat_map(|x| bf16::from_f32(*x).to_le_bytes())
        .collect()
}

/// Codes are packed in MLX's affine layout: element `j` of a word sits at
/// bits `j * bits`, so a 0..15 ramp packs to 0x76543210, 0xFEDCBA98.
#[test]
fn packing_matches_the_mlx_affine_layout() {
    let w: Vec<f32> = (0..64).map(|i| (i % 16) as f32).collect();
    let (words, scales, biases) = quantize(&w, 64, 4, 64).unwrap();
    assert_eq!((scales[0].to_f32(), biases[0].to_f32()), (1.0, 0.0));
    assert_eq!(&words[..2], &[0x7654_3210, 0xFEDC_BA98]);
    let w8: Vec<f32> = (0..64).map(|i| (i % 4) as f32 * 85.0).collect();
    let (words, ..) = quantize(&w8, 64, 8, 64).unwrap();
    assert_eq!(words[0], 0xFF_AA_55_00);
}

/// Every reconstructed weight is within half a step of the original, plus
/// the BF16 rounding of the group's scale and bias.
#[test]
fn round_trip_error_is_bounded_per_group() {
    let w = ramp(8 * 128, 0.3);
    for bits in [4, 8] {
        let (words, scales, biases) = quantize(&w, 128, bits, 64).unwrap();
        let back = dequantize(&words, &scales, &biases, bits, 64);
        assert_eq!(back.len(), w.len());
        for (g, (orig, got)) in w.chunks(64).zip(back.chunks(64)).enumerate() {
            let s = scales[g].to_f32();
            let span = orig.iter().fold(0f32, |m, v| m.max(v.abs()));
            let tol = s * 0.5 + span * 2f32.powi(-7) + 1e-7;
            for (a, b) in orig.iter().zip(got) {
                assert!(
                    (a - b).abs() <= tol,
                    "bits {bits} group {g}: {a} vs {b} (tol {tol})"
                );
            }
        }
    }
    // A constant group reconstructs exactly.
    let flat = vec![0.125f32; 64];
    let (words, scales, biases) = quantize(&flat, 64, 4, 64).unwrap();
    assert_eq!(dequantize(&words, &scales, &biases, 4, 64), flat);
}

#[test]
fn quantize_refuses_malformed_input() {
    assert!(quantize(&[0.0; 64], 64, 3, 64)
        .unwrap_err()
        .is("QUANTIZE_INPUT"));
    assert!(quantize(&[0.0; 96], 96, 4, 64)
        .unwrap_err()
        .is("QUANTIZE_INPUT"));
    let mut w = vec![0.0; 64];
    w[5] = f32::NAN;
    assert!(quantize(&w, 64, 4, 64).unwrap_err().is("QUANTIZE_INPUT"));
}

#[test]
fn unsupported_architecture_variants_are_refused() {
    for (key, value) in [
        ("alibi", json!(true)),
        ("weight_tying", json!(true)),
        ("activation_type", json!("gelu")),
        ("block_type", json!("sequential")),
        ("include_bias", json!(true)),
        ("scale_logits", json!(true)),
        ("rope_scaling", json!({"type": "linear"})),
        ("model_type", json!("llama")),
        ("n_kv_heads", json!(3)),
    ] {
        let err = LladaConfig::from_hf(&config(&[(key, value)]), 4, 8).unwrap_err();
        assert!(err.is("LLADA_CONFIG_UNSUPPORTED"), "{key}");
    }
    assert!(LladaConfig::from_hf(&config(&[]), 5, 8)
        .unwrap_err()
        .is("LLADA_CONFIG_UNSUPPORTED"));
    let c = LladaConfig::from_hf(&config(&[]), 4, 8).unwrap();
    assert_eq!((c.head_dim, c.mask_token, c.vocab), (32, 256, 320));
}

/// Feeding every upstream tensor yields a safetensors artifact the runner
/// parses, classified as diffusion, with the renamed quantized layout and
/// weights that dequantize back to the inputs.
#[test]
fn packer_emits_a_complete_diffusion_artifact() {
    let tokenizer = crate::tokenizer::tiny_json_for_tests(MASK_TOKEN);
    let mut packer = LladaPacker::new(&config(&[]), &tokenizer, 4, 8).unwrap();
    let (h, i, v) = (64, 128, 320);
    let mut feed: Vec<(String, Vec<usize>)> = vec![
        ("model.transformer.wte.weight".into(), vec![v, h]),
        ("model.transformer.ln_f.weight".into(), vec![h]),
        ("model.transformer.ff_out.weight".into(), vec![v, h]),
    ];
    for (leaf, shape) in [
        ("attn_norm", vec![h]),
        ("ff_norm", vec![h]),
        ("q_proj", vec![h, h]),
        ("k_proj", vec![h, h]),
        ("v_proj", vec![h, h]),
        ("attn_out", vec![h, h]),
        ("ff_proj", vec![i, h]),
        ("up_proj", vec![i, h]),
        ("ff_out", vec![h, i]),
    ] {
        feed.push((format!("model.transformer.blocks.0.{leaf}.weight"), shape));
    }
    let gate = ramp(i * h, 7.0);
    for (k, (name, shape)) in feed.iter().enumerate() {
        let values = if name.ends_with("0.ff_proj.weight") {
            gate.clone()
        } else {
            ramp(shape.iter().product(), k as f32)
        };
        // The packer refuses the artifact until the last tensor arrives.
        packer
            .add(name, "BF16", shape, &bf16_bytes(&values))
            .unwrap();
    }
    let duplicate = packer.add(
        &feed[0].0,
        "BF16",
        &feed[0].1,
        &bf16_bytes(&ramp(v * h, 0.0)),
    );
    assert!(duplicate.unwrap_err().is("LLADA_TENSOR_SHAPE"));
    let bytes = packer.finish().unwrap();
    let idx = crate::safetensors::parse(&bytes).unwrap();
    assert_eq!(
        idx.metadata
            .get("enclave_adapter.backend")
            .map(String::as_str),
        Some(BACKEND)
    );
    assert_eq!(
        idx.metadata.get("is_causal").map(String::as_str),
        Some("false")
    );
    let features = crate::topology::detect(&idx);
    assert_eq!(
        crate::topology::structural_class(&features).unwrap(),
        crate::manifest::ExecutionClass::DiscreteDiffusion
    );
    assert!(features.generative_lm_head);
    assert_eq!(idx.shape("lm_head.weight"), Some(&[v, h * 8 / 32][..]));
    assert_eq!(
        idx.shape("model.layers.0.mlp.gate_proj.weight"),
        Some(&[i, h * 4 / 32][..])
    );
    assert_eq!(
        idx.shape("model.layers.0.mlp.gate_proj.scales"),
        Some(&[i, h / 64][..])
    );
    // The SiLU-side projection (`ff_proj`) became gate_proj, losslessly up to 4-bit error.
    let t = |name: &str| &idx.tensors[name];
    let slice = |name: &str| {
        let t = t(name);
        &bytes[t.range.0..t.range.1]
    };
    let words: Vec<u32> = slice("model.layers.0.mlp.gate_proj.weight")
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .collect();
    let halves = |name: &str| -> Vec<bf16> {
        slice(name)
            .chunks_exact(2)
            .map(|b| bf16::from_le_bytes([b[0], b[1]]))
            .collect()
    };
    let back = dequantize(
        &words,
        &halves("model.layers.0.mlp.gate_proj.scales"),
        &halves("model.layers.0.mlp.gate_proj.biases"),
        4,
        64,
    );
    let worst = gate
        .iter()
        .zip(&back)
        .map(|(a, b)| (a - b).abs())
        .fold(0f32, f32::max);
    assert!(worst < 0.1 / 15.0, "{worst}");
}

#[test]
fn packer_refuses_unknown_missing_and_misshapen_tensors() {
    let tokenizer = crate::tokenizer::tiny_json_for_tests(MASK_TOKEN);
    let mut packer = LladaPacker::new(&config(&[]), &tokenizer, 4, 8).unwrap();
    let one = bf16_bytes(&[0.0; 64]);
    assert!(packer
        .add(
            "model.transformer.blocks.0.lora.weight",
            "BF16",
            &[64],
            &one
        )
        .unwrap_err()
        .is("LLADA_UNKNOWN_TENSOR"));
    assert!(packer
        .add(
            "model.transformer.blocks.1.attn_norm.weight",
            "BF16",
            &[64],
            &one
        )
        .unwrap_err()
        .is("LLADA_UNKNOWN_TENSOR"));
    assert!(packer
        .add(
            "model.transformer.blocks.00.attn_norm.weight",
            "BF16",
            &[64],
            &one
        )
        .unwrap_err()
        .is("LLADA_UNKNOWN_TENSOR"));
    assert!(packer
        .add("model.transformer.ln_f.weight", "BF16", &[32, 2], &one)
        .unwrap_err()
        .is("LLADA_TENSOR_SHAPE"));
    assert!(packer
        .add("model.transformer.ln_f.weight", "F16", &[64], &one)
        .unwrap_err()
        .is("LLADA_SOURCE_DTYPE"));
    packer
        .add("model.transformer.ln_f.weight", "BF16", &[64], &one)
        .unwrap();
    assert!(packer.finish().unwrap_err().is("LLADA_TENSOR_MISSING"));
    // A tokenizer without the configured mask token is refused.
    let other = crate::tokenizer::tiny_json_for_tests("<|end|>");
    assert!(LladaPacker::new(&config(&[]), &other, 4, 8)
        .err()
        .unwrap()
        .is("LLADA_TOKENIZER_MISMATCH"));
}
