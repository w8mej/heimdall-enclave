//! The closed tokenizer must reproduce the `tokenizers` library on every
//! recorded LLaDA-8B-Instruct case (tests/data/llada-tokenizer-golden.json,
//! from scripts/golden-llada-tokenizer.py). The pinned tokenizer.json comes
//! from scripts/fetch-trained-model.py llada; without it the test reports a
//! skip unless depot_REQUIRE_LLADA is set.

use enclave_model_runnerd::dfa::{ArgSchema, Dfa, Lattice, Trellis};
use enclave_model_runnerd::token_lattice::{TokenLattice, VocabTrie};
use enclave_model_runnerd::tokenizer::Tokenizer;
use sha2::{Digest, Sha256};

#[test]
fn closed_tokenizer_matches_reference_on_every_recorded_llada_case() {
    let golden: serde_json::Value = serde_json::from_str(include_str!("data/llada-tokenizer-golden.json")).unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/llada-8b-instruct/tokenizer.json");
    let Ok(bytes) = std::fs::read(&path) else {
        assert!(std::env::var_os("depot_REQUIRE_LLADA").is_none(), "pinned tokenizer.json required");
        eprintln!("LLADA_TOKENIZER_CHECKED=false; pinned tokenizer.json absent");
        return;
    };
    assert_eq!(hex::encode(Sha256::digest(&bytes)), golden["tokenizer_sha256"].as_str().unwrap());
    let tokenizer = Tokenizer::from_hf_json(std::str::from_utf8(&bytes).unwrap()).unwrap();
    let ids = |v: &serde_json::Value| -> Vec<u32> { v.as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u32).collect() };
    let cases = golden["cases"].as_array().unwrap();
    for case in cases {
        let text = case["text"].as_str().unwrap();
        let expected = ids(&case["ids"]);
        assert_eq!(tokenizer.encode(text).unwrap(), expected, "encode {text:?}");
        let decoded = String::from_utf8(tokenizer.decode(&expected).unwrap()).unwrap();
        assert_eq!(decoded, case["decoded"].as_str().unwrap(), "decode {text:?}");
    }
    for (name, id) in golden["special_tokens"].as_object().unwrap() {
        assert_eq!(tokenizer.special(name), Some(id.as_u64().unwrap() as u32), "{name}");
    }
    eprintln!("LLADA_TOKENIZER_CHECKED=true; {} cases, vocab {}", cases.len(), tokenizer.vocab());
}

/// At LLaDA's real vocabulary, the token lattice builds quickly, fits the
/// trellis work budget for a 32-token block, and a grammar-filled block
/// decodes to an accepted document.
#[test]
fn token_lattice_scales_to_the_llada_vocabulary() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/llada-8b-instruct/tokenizer.json");
    let Ok(bytes) = std::fs::read(&path) else {
        assert!(std::env::var_os("depot_REQUIRE_LLADA").is_none(), "pinned tokenizer.json required");
        return;
    };
    let tokenizer = Tokenizer::from_hf_json(std::str::from_utf8(&bytes).unwrap()).unwrap();
    let end = tokenizer.special("<|endoftext|>").unwrap();
    let started = std::time::Instant::now();
    let trie = VocabTrie::build(&tokenizer).unwrap();
    let trie_time = started.elapsed();
    // Held for the life of a binding inside the runner's resident ceiling.
    assert!(trie.heap_bytes() < 4 << 20, "trie {} bytes over {} nodes", trie.heap_bytes(), trie.nodes());
    let schema = ArgSchema::Object(vec![
        ("priority".into(), ArgSchema::Enum(["routine", "important", "urgent", "critical"].map(String::from).to_vec())),
        ("count".into(), ArgSchema::UInt { max_digits: 4 }),
    ]);
    let dfa = Dfa::compile(&schema).unwrap();
    let started = std::time::Instant::now();
    let lattice = TokenLattice::build(&dfa, &trie, end).unwrap();
    let lattice_time = started.elapsed();
    let len = 32;
    Trellis::check_budget(&lattice, len).unwrap();
    let mut x: Vec<Option<u32>> = vec![None; len];
    let mut tr = Trellis::build(&lattice, &x);
    let (cancel, start, mut budget) = (std::sync::atomic::AtomicBool::new(false), std::time::Instant::now(), 20_000_000usize);
    for i in 0..len {
        let token = tr.permitted(&lattice, i).min().unwrap();
        x[i] = Some(token);
        tr.commit(&lattice, &x, i, &mut budget, &cancel, start + std::time::Duration::from_secs(60)).unwrap();
    }
    let ids: Vec<u32> = x.into_iter().flatten().filter(|t| *t != end).collect();
    let text = tokenizer.decode(&ids).unwrap();
    assert!(dfa.accepts(&text), "{}", String::from_utf8_lossy(&text));
    eprintln!("LLADA_LATTICE: trie {trie_time:?} ({} nodes, {} bytes), lattice {lattice_time:?}, {} states, {} edges, fill {:?}",
        trie.nodes(), trie.heap_bytes(), lattice.states(), lattice.edges(), start.elapsed());
}

