//! The closed tokenizer must reproduce the `tokenizers` library on every
//! recorded Qwen3 case (tests/data/qwen3-eagle3-golden.json). The pinned
//! tokenizer.json comes from scripts/fetch-trained-model.py qwen3; without it
//! the test reports a skip unless MCPMAC_REQUIRE_QWEN3 is set.

use enclave_model_runnerd::tokenizer::Tokenizer;
use sha2::{Digest, Sha256};

#[test]
fn closed_tokenizer_matches_reference_on_every_recorded_qwen3_case() {
    let golden: serde_json::Value = serde_json::from_str(include_str!("data/qwen3-eagle3-golden.json")).unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/qwen3-0.6b/tokenizer.json");
    let Ok(bytes) = std::fs::read(&path) else {
        assert!(std::env::var_os("MCPMAC_REQUIRE_QWEN3").is_none(), "pinned tokenizer.json required");
        eprintln!("QWEN3_TOKENIZER_CHECKED=false; pinned tokenizer.json absent");
        return;
    };
    assert_eq!(hex::encode(Sha256::digest(&bytes)), golden["target"]["tokenizer_sha256"].as_str().unwrap());
    let tokenizer = Tokenizer::from_hf_json(std::str::from_utf8(&bytes).unwrap()).unwrap();
    let ids = |v: &serde_json::Value| -> Vec<u32> { v.as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u32).collect() };
    let cases = golden["tokenizer"].as_array().unwrap();
    for case in cases {
        let text = case["text"].as_str().unwrap();
        assert_eq!(tokenizer.encode(text).unwrap(), ids(&case["ids"]), "encode {text:?}");
    }
    for case in golden["cases"].as_array().unwrap() {
        assert_eq!(tokenizer.encode(case["text"].as_str().unwrap()).unwrap(), ids(&case["ids"]));
        let decoded = tokenizer.decode(&ids(&case["greedy_new_ids"])).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), case["greedy_text"].as_str().unwrap());
    }
    for (name, id) in golden["special_tokens"].as_object().unwrap() {
        assert_eq!(tokenizer.special(name), Some(id.as_u64().unwrap() as u32), "{name}");
    }
    eprintln!("QWEN3_TOKENIZER_CHECKED=true; {} cases, vocab {}", cases.len(), tokenizer.vocab());
}
