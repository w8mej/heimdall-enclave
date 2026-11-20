//! The closed tokenizer must reproduce the independent reference tokenizer on
//! every recorded case (tests/data/smollm2-golden.json). The pinned
//! tokenizer.json is fetched with scripts/fetch-trained-model.py smollm2 (plus
//! its tokenizer); without it the test reports a skip unless
//! MCPMAC_REQUIRE_SMOLLM2 is set.

use enclave_model_runnerd::tokenizer::Tokenizer;
use sha2::{Digest, Sha256};

const TOKENIZER_SHA256: &str = "9ca9acddb6525a194ec8ac7a87f24fbba7232a9a15ffa1af0c1224fcd888e47c";

fn pinned_tokenizer() -> Option<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/phase4-trained-mlx/tokenizer.json");
    match std::fs::read(&path) {
        Ok(bytes) => {
            assert_eq!(hex::encode(Sha256::digest(&bytes)), TOKENIZER_SHA256, "pinned tokenizer.json drifted");
            Some(String::from_utf8(bytes).unwrap())
        }
        Err(_) => {
            assert!(std::env::var_os("MCPMAC_REQUIRE_SMOLLM2").is_none(), "pinned tokenizer.json required");
            eprintln!("SMOLLM2_TOKENIZER_CHECKED=false; pinned tokenizer.json absent");
            None
        }
    }
}

#[test]
fn closed_tokenizer_matches_reference_on_every_recorded_case() {
    let Some(json) = pinned_tokenizer() else { return };
    let tokenizer = Tokenizer::from_hf_json(&json).unwrap();
    let golden: serde_json::Value = serde_json::from_str(include_str!("data/smollm2-golden.json")).unwrap();
    let cases = golden["tokenizer"].as_array().unwrap();
    assert!(cases.len() >= 9);
    for case in cases {
        let text = case["text"].as_str().unwrap();
        let expected: Vec<u32> = case["ids"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap() as u32).collect();
        assert_eq!(tokenizer.encode(text).unwrap(), expected, "encode {text:?}");
        assert_eq!(tokenizer.decode(&expected).unwrap(), text.as_bytes(), "decode {text:?}");
    }
    for (name, id) in golden["special_tokens"].as_object().unwrap() {
        assert_eq!(tokenizer.special(name), Some(id.as_u64().unwrap() as u32));
    }
    // The chat prompt encodes to the exact ids the reference model was given.
    let chat = "<|im_start|>user\nWhat is the capital of France?<|im_end|>\n<|im_start|>assistant\n";
    let expected: Vec<u32> = golden["logits"][1]["ids"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap() as u32).collect();
    assert_eq!(tokenizer.encode(chat).unwrap(), expected);
    eprintln!("SMOLLM2_TOKENIZER_CHECKED=true; {} cases", cases.len());
}
